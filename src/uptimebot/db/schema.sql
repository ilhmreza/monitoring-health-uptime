-- UptimeBot schema. Applied idempotently at startup by db/database.py.

-- ---------------------------------------------------------------- monitors
-- Monitor configuration, owned by the web UI. This is the single source of
-- truth: the scheduler re-reads it on every change notification, so edits
-- apply without a container restart.
CREATE TABLE IF NOT EXISTS monitors (
    id                     TEXT PRIMARY KEY,
    name                   TEXT NOT NULL,
    url                    TEXT NOT NULL,
    method                 TEXT NOT NULL DEFAULT 'GET',
    expect_status          TEXT NOT NULL DEFAULT '[200]',
    headers_env            TEXT NOT NULL DEFAULT '{}',
    keyword                TEXT,
    interval_seconds       INTEGER NOT NULL DEFAULT 60,
    timeout_seconds        INTEGER NOT NULL DEFAULT 10,
    failure_threshold      INTEGER NOT NULL DEFAULT 3,
    notify_user_ids        TEXT NOT NULL DEFAULT '[]',
    notify_role_ids        TEXT NOT NULL DEFAULT '[]',
    notify_on              TEXT NOT NULL DEFAULT '["down","recovery","ssl"]',
    ssl_check              INTEGER NOT NULL DEFAULT 1,
    ssl_warn_days          TEXT NOT NULL DEFAULT '[30,14,7,1]',
    allow_private_network  INTEGER NOT NULL DEFAULT 0,
    enabled                INTEGER NOT NULL DEFAULT 1,
    created_at             TEXT NOT NULL,
    updated_at             TEXT NOT NULL
);

-- ------------------------------------------------------------ monitor_state
-- Runtime state, kept separate from config so editing a monitor never wipes
-- its downtime start time. down_since surviving a container restart is what
-- makes "down for 5h 23m" correct even after a deploy.
CREATE TABLE IF NOT EXISTS monitor_state (
    monitor_id             TEXT PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
    state                  TEXT NOT NULL DEFAULT 'unknown',
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    down_since             TEXT,
    -- Start of the current unbroken run of healthy probes. The counterpart to
    -- down_since, so the UI can answer "how long has it been up" as well as
    -- "how long has it been down". Survives restarts like down_since does.
    up_since               TEXT,
    last_check_at          TEXT,
    last_ok_at             TEXT,
    last_reminder_at       TEXT,
    last_alert_at          TEXT,
    -- Highest SSL severity already announced. Deduplicates warnings so a
    -- 30-day reminder is not repeated on every check.
    ssl_notified_severity  INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------------ checks
-- Append-only probe history. Drives uptime %, latency stats and charts.
CREATE TABLE IF NOT EXISTS checks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    monitor_id    TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    ts            TEXT NOT NULL,
    ok            INTEGER NOT NULL,
    status_code   INTEGER,
    latency_ms    REAL,
    error         TEXT,
    -- FailureKind of the classifier, kept separately from the message so the
    -- incident list can group causes without parsing free text.
    failure_kind  TEXT
);

-- Dashboard and history queries are always "this monitor, this time range,
-- newest first", so a covering index on (monitor_id, ts DESC) is what the
-- read paths want.
CREATE INDEX IF NOT EXISTS idx_checks_monitor_ts ON checks(monitor_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts);

-- ---------------------------------------------------------------- ssl_state
-- Last known certificate facts. Persisted so the UI can render the SSL table
-- without the server making outbound TLS handshakes on every page load.
CREATE TABLE IF NOT EXISTS ssl_state (
    monitor_id    TEXT PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
    not_after     TEXT,
    days_left     INTEGER,
    issuer        TEXT,
    subject_cn    TEXT,
    tls_version   TEXT,
    chain_ok      INTEGER,
    last_checked  TEXT,
    last_error    TEXT,
    -- Severity already computed at check time, so the table does not have to
    -- re-derive it from the monitor's own (mutable) threshold list.
    severity      INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------ discord_users
-- Cache of @username -> User ID resolved from channel message history.
-- Lets the UI still autocomplete if Discord is briefly unreachable.
CREATE TABLE IF NOT EXISTS discord_users (
    user_id          TEXT PRIMARY KEY,
    username         TEXT NOT NULL,
    global_name      TEXT,
    source_channel   TEXT,
    resolved_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_discord_users_username
    ON discord_users(username COLLATE NOCASE);

-- ----------------------------------------------------------------- web_user
-- Single admin account. The bcrypt hash lives here so it can be rotated
-- through the UI; a .env value, when present, takes precedence.
CREATE TABLE IF NOT EXISTS web_user (
    username       TEXT PRIMARY KEY,
    password_hash  TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

-- ---------------------------------------------------------------- audit_log
-- Who changed what, for accountability on a config surface that can silence
-- alerts.
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    actor    TEXT NOT NULL,
    action   TEXT NOT NULL,
    target   TEXT,
    detail   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
