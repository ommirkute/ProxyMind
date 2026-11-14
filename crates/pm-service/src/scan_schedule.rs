//! Scheduled scans: a crawl-and-audit task that starts on its own every
//! hour, day or week (times in UTC). A schedule runs as the human who saved
//! it, through the same gate as a task started by hand; a run is skipped
//! while the previous one is still going.
//!
//! The ticker (`Service::run_scheduler`) runs in processes that stay up: the
//! web UI server and the desktop app. `schedule_tick` takes the time, so
//! tests can drive it. When several processes have the project open, each
//! run is claimed in the database first, so it starts once.

use std::sync::Arc;

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Result, ScanTaskRequest, ScanTaskView, Service, ServiceError};

const MINUTE: i64 = 60_000;
const HOUR: i64 = 60 * MINUTE;
const DAY: i64 = 24 * HOUR;
const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

/// How often a schedule runs (times are UTC, "HH:MM").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Every {
    Hourly,
    Daily { at: String },
    Weekly { day: String, at: String },
}

impl Default for Every {
    fn default() -> Self {
        Every::Daily { at: "02:00".into() }
    }
}

fn parse_hhmm(at: &str) -> std::result::Result<i64, String> {
    let bad = || format!("times are HH:MM in UTC, e.g. 02:30 (got {at:?})");
    let (h, m) = at.trim().split_once(':').ok_or_else(bad)?;
    let (h, m): (i64, i64) = (h.parse().map_err(|_| bad())?, m.parse().map_err(|_| bad())?);
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return Err(bad());
    }
    Ok(h * HOUR + m * MINUTE)
}

fn parse_day(day: &str) -> std::result::Result<i64, String> {
    let d = day.trim().to_ascii_lowercase();
    DAYS.iter()
        .position(|x| d.starts_with(x))
        .map(|i| i as i64)
        .ok_or_else(|| format!("days are mon, tue, wed, thu, fri, sat or sun (got {day:?})"))
}

impl Every {
    fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Every::Hourly => Ok(()),
            Every::Daily { at } => parse_hhmm(at).map(|_| ()),
            Every::Weekly { day, at } => parse_day(day).and(parse_hhmm(at)).map(|_| ()),
        }
    }
}

/// The first time after `now_ms` (epoch milliseconds, UTC) that `every` is due.
pub fn next_run_after(every: &Every, now_ms: i64) -> i64 {
    let day_start = now_ms - now_ms.rem_euclid(DAY);
    match every {
        Every::Hourly => now_ms - now_ms.rem_euclid(HOUR) + HOUR,
        Every::Daily { at } => {
            let t = day_start + parse_hhmm(at).unwrap_or(0);
            if t > now_ms { t } else { t + DAY }
        }
        Every::Weekly { day, at } => {
            // 1970-01-01 was a Thursday (index 3 with Monday = 0).
            let today = (now_ms.div_euclid(DAY) + 3).rem_euclid(7);
            let want = parse_day(day).unwrap_or(0);
            let t = day_start + (want - today).rem_euclid(7) * DAY + parse_hhmm(at).unwrap_or(0);
            if t > now_ms { t } else { t + 7 * DAY }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanSchedule {
    /// 0 for a new schedule.
    pub id: i64,
    pub name: String,
    pub every: Every,
    /// What to run (a profile can fill in the rest).
    pub request: ScanTaskRequest,
    pub enabled: bool,
    /// Set by the service.
    pub created_by: String,
    pub next_run_ms: i64,
    pub last_run_ms: Option<i64>,
    pub last_task: Option<String>,
    pub last_error: Option<String>,
}

fn humans_only(actor: &Actor) -> Result<()> {
    if actor.kind != ActorKind::Human {
        return Err(ServiceError::Invalid("only humans can change scan schedules (they run unattended)".into()));
    }
    Ok(())
}

fn from_row(row: pm_store::ScheduleRow) -> Option<ScanSchedule> {
    let mut s: ScanSchedule = serde_json::from_str(&row.data).ok()?;
    s.id = row.id;
    s.created_by = row.created_by;
    s.enabled = row.enabled;
    s.next_run_ms = row.next_run_ms;
    Some(s)
}

impl Service {
    pub fn schedule_list(&self) -> Result<Vec<ScanSchedule>> {
        Ok(self.store.read(|db| db.list_schedules())?.into_iter().filter_map(from_row).collect())
    }

    fn schedule_get(&self, id: i64) -> Result<ScanSchedule> {
        self.schedule_list()?
            .into_iter()
            .find(|s| s.id == id)
            .ok_or_else(|| ServiceError::NotFound(format!("scan schedule {id}")))
    }

    fn schedule_write(&self, s: &ScanSchedule) -> Result<i64> {
        let row = pm_store::ScheduleRow {
            id: s.id,
            created_by: s.created_by.clone(),
            data: serde_json::to_string(s).map_err(|e| ServiceError::Invalid(e.to_string()))?,
            enabled: s.enabled,
            next_run_ms: s.next_run_ms,
        };
        Ok(self.store.write(|db| db.save_schedule(&row))?)
    }

    /// Adds a schedule (id 0) or changes one. It will run as `actor`.
    pub fn schedule_save(&self, actor: &Actor, mut s: ScanSchedule) -> Result<ScanSchedule> {
        humans_only(actor)?;
        s.name = s.name.trim().to_string();
        if s.name.is_empty() || s.name.len() > 80 {
            return Err(ServiceError::Invalid("a schedule needs a name (up to 80 characters)".into()));
        }
        s.every.validate().map_err(ServiceError::Invalid)?;
        crate::replay::parse_url_endpoint(&s.request.url)?;
        if let Some(p) = s.request.profile.as_deref().filter(|p| !p.is_empty()) {
            self.scan_profile(p)?;
        }
        let known = |c: &str| pm_scan::active::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c);
        if let Some(bad) = s.request.checks.iter().find(|c| !known(c)) {
            return Err(ServiceError::Invalid(format!("unknown check {bad}")));
        }
        if s.id != 0 {
            let old = self.schedule_get(s.id)?;
            s.last_run_ms = old.last_run_ms;
            s.last_task = old.last_task;
            s.last_error = old.last_error;
        } else if self.store.read(|db| db.list_schedules())?.len() >= 50 {
            return Err(ServiceError::Invalid("at most 50 schedules".into()));
        }
        // The approval in a request is single-use: never replay it.
        s.request.approval_id = None;
        s.created_by = actor.id();
        s.next_run_ms = next_run_after(&s.every, pm_core::now_ms());
        s.id = self.schedule_write(&s)?;
        self.audit(&actor.id(), "scan_schedule_save", json!(s), "allow")?;
        Ok(s)
    }

    pub fn schedule_delete(&self, actor: &Actor, id: i64) -> Result<bool> {
        humans_only(actor)?;
        let deleted = self.store.write(|db| db.delete_schedule(id))?;
        self.audit(&actor.id(), "scan_schedule_delete", json!({ "id": id }), if deleted { "allow" } else { "noop" })?;
        Ok(deleted)
    }

    /// Starts a schedule's scan now (its regular times don't change).
    pub fn schedule_run_now(self: &Arc<Self>, actor: &Actor, id: i64) -> Result<ScanTaskView> {
        humans_only(actor)?;
        let mut s = self.schedule_get(id)?;
        let v = self.fire(&mut s, pm_core::now_ms())?;
        self.schedule_write(&s)?;
        Ok(v)
    }

    fn fire(self: &Arc<Self>, s: &mut ScanSchedule, now_ms: i64) -> Result<ScanTaskView> {
        let owner = Actor::parse(&s.created_by).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        s.last_run_ms = Some(now_ms);
        let r = self.scan_task_start_from(&owner, s.request.clone(), Some(s.id));
        match &r {
            Ok(v) => {
                s.last_task = Some(v.task_id.clone());
                s.last_error = None;
            }
            Err(e) => s.last_error = Some(e.to_string()),
        }
        self.audit(
            &owner.id(),
            "scan_schedule_fire",
            json!({ "schedule": s.id, "task": s.last_task, "error": s.last_error }),
            if r.is_ok() { "allow" } else { "error" },
        )?;
        r
    }

    /// Starts every enabled schedule that is due at `now_ms`. Returns the
    /// ids of the tasks started.
    pub fn schedule_tick(self: &Arc<Self>, now_ms: i64) -> Result<Vec<String>> {
        let mut started = Vec::new();
        for mut s in self.schedule_list()? {
            if !s.enabled || s.next_run_ms > now_ms {
                continue;
            }
            let next = next_run_after(&s.every, now_ms);
            if !self.store.write(|db| db.claim_schedule(s.id, s.next_run_ms, next))? {
                continue; // another process got there first
            }
            s.next_run_ms = next;
            if s.last_task.as_deref().is_some_and(|t| self.scan_task_running(t)) {
                s.last_error = Some("skipped a run: the previous one was still going".into());
            } else if let Ok(v) = self.fire(&mut s, now_ms) {
                started.push(v.task_id);
            }
            self.schedule_write(&s)?;
        }
        Ok(started)
    }

    /// Checks the schedules every 30 seconds, for as long as the process runs.
    pub async fn run_scheduler(self: Arc<Self>) {
        loop {
            if let Err(e) = self.schedule_tick(pm_core::now_ms()) {
                tracing::warn!("scan schedules: {e}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2026-10-24 (a Saturday) 10:15 UTC.
    const NOW: i64 = 1_792_836_900_000;

    #[test]
    fn next_runs() {
        assert_eq!((NOW.div_euclid(DAY) + 3).rem_euclid(7), 5, "Saturday");
        assert_eq!(next_run_after(&Every::Hourly, NOW), NOW + 45 * MINUTE);
        let daily = |at: &str| next_run_after(&Every::Daily { at: at.into() }, NOW);
        assert_eq!(daily("10:30"), NOW + 15 * MINUTE);
        assert_eq!(daily("10:15"), NOW + DAY, "now is already past");
        assert_eq!(daily("02:00"), NOW - 8 * HOUR - 15 * MINUTE + DAY);
        let weekly = |day: &str, at: &str| next_run_after(&Every::Weekly { day: day.into(), at: at.into() }, NOW);
        assert_eq!(weekly("sat", "11:15"), NOW + HOUR);
        assert_eq!(weekly("sat", "09:15"), NOW - HOUR + 7 * DAY);
        assert_eq!(weekly("Monday", "10:15"), NOW + 2 * DAY);
    }

    #[test]
    fn bad_times_are_refused() {
        assert!(Every::Daily { at: "24:00".into() }.validate().is_err());
        assert!(Every::Daily { at: "9".into() }.validate().is_err());
        assert!(Every::Weekly { day: "someday".into(), at: "09:00".into() }.validate().is_err());
        assert!(Every::Weekly { day: "fri".into(), at: "23:59".into() }.validate().is_ok());
    }
}
