//! Testing time windows such as `Mon-Fri 09:00-18:00`.

use jiff::civil::{Time, Weekday};

use crate::PolicyError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    first_day: Weekday,
    last_day: Weekday,
    start: Time,
    /// `None` means 24:00 (end of day).
    end: Option<Time>,
}

fn weekday(s: &str) -> Option<Weekday> {
    Some(match s {
        "Mon" => Weekday::Monday,
        "Tue" => Weekday::Tuesday,
        "Wed" => Weekday::Wednesday,
        "Thu" => Weekday::Thursday,
        "Fri" => Weekday::Friday,
        "Sat" => Weekday::Saturday,
        "Sun" => Weekday::Sunday,
        _ => return None,
    })
}

fn hhmm(s: &str) -> Option<Option<Time>> {
    if s == "24:00" {
        return Some(None);
    }
    let (h, m) = s.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    Time::new(h.parse().ok()?, m.parse().ok()?, 0, 0).ok().map(Some)
}

impl TimeWindow {
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let bad = || PolicyError::Roe(format!("bad time window {s:?} (expected e.g. \"Mon-Fri 09:00-18:00\")"));
        let (days, times) = s.trim().split_once(' ').ok_or_else(bad)?;
        let (first, last) = match days.split_once('-') {
            Some((a, b)) => (weekday(a).ok_or_else(bad)?, weekday(b).ok_or_else(bad)?),
            None => {
                let d = weekday(days).ok_or_else(bad)?;
                (d, d)
            }
        };
        let (a, b) = times.split_once('-').ok_or_else(bad)?;
        let start = hhmm(a).flatten().ok_or_else(bad)?;
        let end = hhmm(b).ok_or_else(bad)?;
        if end == Some(start) {
            return Err(bad());
        }
        Ok(Self { first_day: first, last_day: last, start, end })
    }

    fn day_in_range(&self, d: Weekday) -> bool {
        let (f, l, d) =
            (self.first_day.to_monday_zero_offset(), self.last_day.to_monday_zero_offset(), d.to_monday_zero_offset());
        if f <= l { (f..=l).contains(&d) } else { d >= f || d <= l }
    }

    /// Whether a local date-time falls in this window. A window whose end is
    /// before its start runs past midnight into the next day.
    pub fn contains(&self, local: jiff::civil::DateTime) -> bool {
        let (day, time) = (local.weekday(), local.time());
        match self.end {
            None => self.day_in_range(day) && time >= self.start,
            Some(end) if end > self.start => self.day_in_range(day) && time >= self.start && time < end,
            Some(end) => {
                (self.day_in_range(day) && time >= self.start) || (self.day_in_range(day.previous()) && time < end)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;

    #[test]
    fn office_hours() {
        let w = TimeWindow::parse("Mon-Fri 09:00-18:00").unwrap();
        // 2026-10-19 is a Monday.
        assert!(w.contains(date(2026, 10, 19).at(9, 0, 0, 0)));
        assert!(w.contains(date(2026, 10, 23).at(17, 59, 0, 0)));
        assert!(!w.contains(date(2026, 10, 23).at(18, 0, 0, 0)));
        assert!(!w.contains(date(2026, 10, 24).at(12, 0, 0, 0)));
    }

    #[test]
    fn overnight_and_wrapping_days() {
        let w = TimeWindow::parse("Fri-Mon 22:00-06:00").unwrap();
        assert!(w.contains(date(2026, 10, 23).at(23, 0, 0, 0))); // Fri night
        assert!(w.contains(date(2026, 10, 24).at(5, 0, 0, 0))); // Sat early (from Fri)
        assert!(w.contains(date(2026, 10, 27).at(5, 0, 0, 0))); // Tue early (from Mon)
        assert!(!w.contains(date(2026, 10, 28).at(5, 0, 0, 0))); // Wed early (Tue not in range)
        assert!(TimeWindow::parse("Sat 00:00-24:00").unwrap().contains(date(2026, 10, 24).at(23, 59, 0, 0)));
    }

    #[test]
    fn rejects_bad_windows() {
        for s in ["Mon-Fri", "Mon-Fri 9:00-18:00", "Funday 09:00-10:00", "Mon 10:00-10:00", "Mon 25:00-26:00"] {
            assert!(TimeWindow::parse(s).is_err(), "{s}");
        }
    }
}
