-- ReaperWatch console storage schema.
--
-- `events` mirrors the process_create schema the agent emits, flattened into
-- columns for indexing/filtering, plus `raw_json` (the original event) for
-- full drill-down in the Hunt view.
--
-- Note: `id` (not the agent's `sequence_id`) is the primary key. sequence_id is
-- a per-process counter that RESTARTS AT 0 every time the agent restarts, so it
-- is not safe as a globally unique key here -- we keep it as `agent_seq` for
-- reference only.

CREATE TABLE IF NOT EXISTS events (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_seq        INTEGER,
  ts               TEXT NOT NULL,
  event_type       TEXT NOT NULL,

  proc_pid         INTEGER,
  proc_name        TEXT,
  proc_path        TEXT,
  proc_cmdline     TEXT,
  proc_sha256      TEXT,
  proc_md5         TEXT,
  proc_signed      INTEGER,
  proc_signer      TEXT,

  parent_pid       INTEGER,
  parent_name      TEXT,
  parent_path      TEXT,
  parent_cmdline   TEXT,
  parent_sha256    TEXT,

  grandparent_pid  INTEGER,
  grandparent_name TEXT,

  user_name        TEXT,
  user_domain      TEXT,
  user_sid         TEXT,
  user_is_admin    INTEGER,
  user_is_system   INTEGER,

  host_hostname    TEXT,
  host_os          TEXT,
  host_arch        TEXT,

  flag_is_lolbin      INTEGER,
  flag_unusual_parent INTEGER,
  flag_is_hollow      INTEGER,
  flag_is_injected    INTEGER,

  raw_json         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts          ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type        ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_proc_name   ON events(proc_name);
CREATE INDEX IF NOT EXISTS idx_events_proc_sha256 ON events(proc_sha256);
CREATE INDEX IF NOT EXISTS idx_events_proc_signer ON events(proc_signer);
CREATE INDEX IF NOT EXISTS idx_events_user_name   ON events(user_name);

CREATE TABLE IF NOT EXISTS alerts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id   INTEGER NOT NULL REFERENCES events(id),
  ts         TEXT NOT NULL,
  severity   TEXT NOT NULL,   -- critical | high | medium | low
  mitre_id   TEXT,
  mitre_name TEXT,
  rule_name  TEXT NOT NULL,
  title      TEXT NOT NULL,
  detail     TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_mitre    ON alerts(mitre_id);

-- How far the ingestor has read into events.jsonl, so a restart resumes instead
-- of re-processing (and re-alerting on) the whole file from the beginning.
CREATE TABLE IF NOT EXISTS ingest_state (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  byte_offset INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO ingest_state (id, byte_offset) VALUES (1, 0);
