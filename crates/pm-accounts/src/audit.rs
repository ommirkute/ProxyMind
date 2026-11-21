//! The security log: account events in an append-only table, each record's MAC chained to the previous one under the
//! audit-chain key. Detail strings are fixed words and ids; a secret never goes in (the tests grep for the ones used).
//! Not yet covered by signed checkpoints, so a truncated tail is not detected (ADR-0022 lists them later).

use ring::hmac;
use rusqlite::Connection;

use crate::error::Result;
use crate::model::SecurityEvent;
use crate::store::Accounts;
use crate::util::{clip, ct_eq};

/// `fields` are kind, user id (empty for none), actor, address (empty for none) and detail.
fn record_mac(key: &hmac::Key, prev: &[u8], at: i64, fields: [&str; 5]) -> Vec<u8> {
    let mut ctx = hmac::Context::with_key(key);
    let mut field = |b: &[u8]| {
        ctx.update(&u32::try_from(b.len()).unwrap_or(u32::MAX).to_be_bytes());
        ctx.update(b);
    };
    field(prev);
    field(&at.to_be_bytes());
    for f in fields {
        field(f.as_bytes());
    }
    ctx.sign().as_ref().to_vec()
}

impl Accounts {
    /// Appends an entry. Called inside the transaction of the change it records.
    pub(crate) fn audit(
        &self,
        conn: &Connection,
        kind: &str,
        user_id: Option<&str>,
        actor: &str,
        addr: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        use rusqlite::OptionalExtension;
        let prev: Vec<u8> = conn
            .query_row("SELECT mac FROM security_audit ORDER BY seq DESC LIMIT 1", [], |r| r.get(0))
            .optional()?
            .unwrap_or_else(|| vec![0u8; 32]);
        let at = self.now();
        let addr = addr.map(|a| clip(a, 64));
        let detail = clip(detail, 200);
        let mac = record_mac(
            &self.keys.audit,
            &prev,
            at,
            [kind, user_id.unwrap_or(""), actor, addr.as_deref().unwrap_or(""), &detail],
        );
        conn.execute(
            "INSERT INTO security_audit (at, kind, user_id, actor, client_addr, detail, prev, mac) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![at, kind, user_id, actor, addr, detail, prev, mac],
        )?;
        Ok(())
    }

    /// The newest `limit` entries, newest first.
    pub fn security_log(&self, limit: usize) -> Result<Vec<SecurityEvent>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT seq, at, kind, user_id, actor, client_addr, detail FROM security_audit ORDER BY seq DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |r| {
            Ok(SecurityEvent {
                seq: r.get(0)?,
                at: r.get(1)?,
                kind: r.get(2)?,
                user_id: r.get(3)?,
                actor: r.get(4)?,
                client_addr: r.get(5)?,
                detail: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Recomputes the chain. Returns the number of entries, or the sequence number of the first bad one.
    pub fn verify_security_log(&self) -> Result<std::result::Result<usize, i64>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT seq, at, kind, user_id, actor, client_addr, detail, prev, mac FROM security_audit ORDER BY seq",
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_prev = vec![0u8; 32];
        let mut n = 0;
        while let Some(r) = rows.next()? {
            let seq: i64 = r.get(0)?;
            let (at, kind, user, actor, addr, detail): (i64, String, Option<String>, String, Option<String>, String) =
                (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?);
            let (prev, mac): (Vec<u8>, Vec<u8>) = (r.get(7)?, r.get(8)?);
            let want = record_mac(
                &self.keys.audit,
                &prev,
                at,
                [&kind, user.as_deref().unwrap_or(""), &actor, addr.as_deref().unwrap_or(""), &detail],
            );
            if !ct_eq(&prev, &expected_prev) || !ct_eq(&mac, &want) {
                return Ok(Err(seq));
            }
            expected_prev = mac;
            n += 1;
        }
        Ok(Ok(n))
    }
}
