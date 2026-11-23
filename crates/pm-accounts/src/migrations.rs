//! `server.db` schema. Append-only: never edit a released entry (tracked in `user_version`).
//!
//! Tables ADR-0022 lists that later steps add as new entries: `oidc_providers` (step 8) and `checkpoints`. `tokens`
//! is the second entry (step 5). Passkeys (step 7) need no schema change: a `credentials` row of kind `passkey` with the credential id
//! in `external_id`, the COSE public key in `secret`, the signature counter in `counter` and transports, AAGUID and
//! name in `meta` / `label`. OIDC links use kind `oidc` with `(iss, sub)` in `external_id`.

pub(crate) const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    server_admin  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
);

CREATE TABLE credentials (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL CHECK (kind IN ('password', 'totp', 'passkey', 'oidc')),
    label        TEXT,
    external_id  BLOB,
    secret       BLOB,
    enabled      INTEGER NOT NULL DEFAULT 1,
    counter      INTEGER NOT NULL DEFAULT 0,
    meta         TEXT,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
);
CREATE INDEX credentials_user ON credentials(user_id);
CREATE UNIQUE INDEX credentials_one_per_user ON credentials(user_id, kind) WHERE kind IN ('password', 'totp');
CREATE UNIQUE INDEX credentials_external ON credentials(kind, external_id) WHERE external_id IS NOT NULL;

CREATE TABLE recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    used_at    INTEGER,
    UNIQUE (user_id, code_hash)
);

CREATE TABLE sessions (
    id_hash             BLOB PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_method         TEXT NOT NULL,
    created_at          INTEGER NOT NULL,
    authenticated_at    INTEGER NOT NULL,
    last_seen_at        INTEGER NOT NULL,
    idle_expires_at     INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    rotated_from        BLOB,
    client_addr         TEXT,
    user_agent          TEXT,
    revoked_at          INTEGER,
    revoked_reason      TEXT
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE pending_logins (
    id_hash     BLOB PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('second_factor', 'enrol')),
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    client_addr TEXT
);

CREATE TABLE memberships (
    project_id TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'tester', 'viewer')),
    created_at INTEGER NOT NULL,
    created_by TEXT,
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE invites (
    id         TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'tester', 'viewer')),
    project_id TEXT,
    created_by TEXT NOT NULL REFERENCES users(id),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER,
    used_by    TEXT,
    revoked_at INTEGER
);

CREATE TABLE setup_tokens (
    id         TEXT PRIMARY KEY,
    token_hash BLOB NOT NULL UNIQUE,
    kind       TEXT NOT NULL CHECK (kind IN ('bootstrap', 'reset')),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE login_throttle (
    scope           TEXT NOT NULL CHECK (scope IN ('account', 'address')),
    key             TEXT NOT NULL,
    failures        INTEGER NOT NULL,
    last_failure_at INTEGER NOT NULL,
    blocked_until   INTEGER NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE security_audit (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    at          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    user_id     TEXT,
    actor       TEXT NOT NULL,
    client_addr TEXT,
    detail      TEXT NOT NULL,
    prev        BLOB NOT NULL,
    mac         BLOB NOT NULL
);
"#,
    r#"
CREATE TABLE tokens (
    id             TEXT PRIMARY KEY,
    token_hash     BLOB NOT NULL UNIQUE,
    kind           TEXT NOT NULL CHECK (kind IN ('agent', 'ci', 'plugin')),
    name           TEXT NOT NULL,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id     TEXT NOT NULL,
    role           TEXT NOT NULL CHECK (role IN ('tester', 'viewer')),
    tier_cap       TEXT,
    created_at     INTEGER NOT NULL,
    created_by     TEXT NOT NULL,
    expires_at     INTEGER NOT NULL,
    last_used_at   INTEGER,
    use_count      INTEGER NOT NULL DEFAULT 0,
    revoked_at     INTEGER,
    revoked_reason TEXT
);
CREATE INDEX tokens_user ON tokens(user_id);
CREATE INDEX tokens_project ON tokens(project_id);
"#,
];

pub(crate) fn apply(conn: &mut rusqlite::Connection) -> crate::error::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let done = usize::try_from(version).unwrap_or(0);
    if done > MIGRATIONS.len() {
        return Err(crate::error::AccountError::NewerSchema(version));
    }
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(done) {
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
    }
    Ok(())
}
