'use strict';

// Tails data/events.jsonl: on each tick, reads only the bytes appended since
// the last read (tracked in ingest_state), parses each complete line as one
// event, inserts it, and runs the detection matcher over it.

const fs = require('node:fs');
const { EVENTS_FILE } = require('../storage/db');

function getOffset(db) {
  const row = db.prepare('SELECT byte_offset FROM ingest_state WHERE id = 1').get();
  return row ? row.byte_offset : 0;
}

function setOffset(db, offset) {
  db.prepare('UPDATE ingest_state SET byte_offset = ? WHERE id = 1').run(offset);
}

function insertEvent(db, evt) {
  const p = evt.process || {}, par = evt.parent || {}, gp = evt.grandparent || {},
        u = evt.user || {}, h = evt.host || {}, f = evt.flags || {};

  const stmt = db.prepare(`
    INSERT INTO events (
      agent_seq, ts, event_type,
      proc_pid, proc_name, proc_path, proc_cmdline, proc_sha256, proc_md5, proc_signed, proc_signer,
      parent_pid, parent_name, parent_path, parent_cmdline, parent_sha256,
      grandparent_pid, grandparent_name,
      user_name, user_domain, user_sid, user_is_admin, user_is_system,
      host_hostname, host_os, host_arch,
      flag_is_lolbin, flag_unusual_parent, flag_is_hollow, flag_is_injected,
      raw_json
    ) VALUES (?,?,?, ?,?,?,?,?,?,?,?, ?,?,?,?,?, ?,?, ?,?,?,?,?, ?,?,?, ?,?,?,?, ?)
  `);

  const info = stmt.run(
    evt.sequence_id ?? null, evt.timestamp ?? null, evt.event_type ?? null,
    p.pid ?? null, p.name ?? null, p.path ?? null, p.cmdline ?? null,
    p.sha256 ?? null, p.md5 ?? null, p.signed ? 1 : 0, p.signer ?? null,
    par.pid ?? null, par.name ?? null, par.path ?? null, par.cmdline ?? null, par.sha256 ?? null,
    gp.pid ?? null, gp.name ?? null,
    u.name ?? null, u.domain ?? null, u.sid ?? null, u.is_admin ? 1 : 0, u.is_system ? 1 : 0,
    h.hostname ?? null, h.os ?? null, h.arch ?? null,
    f.is_lolbin ? 1 : 0, f.unusual_parent ? 1 : 0, f.is_hollow ? 1 : 0, f.is_injected ? 1 : 0,
    JSON.stringify(evt),
  );
  return Number(info.lastInsertRowid);
}

function insertAlert(db, eventId, alert) {
  db.prepare(`
    INSERT INTO alerts (event_id, ts, severity, mitre_id, mitre_name, rule_name, title, detail)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    eventId, alert.ts, alert.severity, alert.mitreId ?? null, alert.mitreName ?? null,
    alert.ruleName, alert.title, alert.detail ?? null,
  );
}

// Reads and processes whatever is new in events.jsonl since the last call.
// Returns the number of events ingested. `matchEvent(evt) -> alert[]` is
// injected so this module doesn't depend on the detection engine directly.
function processNewData(db, matchEvent) {
  if (!fs.existsSync(EVENTS_FILE)) return 0;

  const stat = fs.statSync(EVENTS_FILE);
  let offset = getOffset(db);
  if (stat.size < offset) offset = 0;  // file was truncated/rotated; start over
  if (stat.size <= offset) return 0;   // nothing new

  const length = stat.size - offset;
  const buffer = Buffer.alloc(length);
  const fd = fs.openSync(EVENTS_FILE, 'r');
  fs.readSync(fd, buffer, 0, length, offset);
  fs.closeSync(fd);

  const text = buffer.toString('utf8');
  const lines = text.split('\n');
  // The last element is either '' (text ended with \n) or a partial, not-yet-
  // fully-written line -- in both cases it is NOT a complete line, so it is
  // deliberately excluded and re-read on the next tick.
  const complete = lines.slice(0, -1);

  let consumedBytes = 0, count = 0;
  for (const line of complete) {
    // Bytes are consumed regardless of what happens below: a permanently
    // malformed line must not be retried forever and block everything after it.
    consumedBytes += Buffer.byteLength(line, 'utf8') + 1;  // +1 for the '\n'
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      const evt = JSON.parse(trimmed);
      const eventId = insertEvent(db, evt);
      for (const alert of matchEvent(evt)) insertAlert(db, eventId, alert);
      count++;
    } catch (err) {
      console.error('[ingestor] skipping malformed event line:', err.message);
    }
  }

  setOffset(db, offset + consumedBytes);
  return count;
}

function startIngestor(db, matchEvent, { intervalMs = 1000 } = {}) {
  const tick = () => {
    try {
      const n = processNewData(db, matchEvent);
      if (n > 0) console.log(`[ingestor] ingested ${n} event(s)`);
    } catch (err) {
      console.error('[ingestor] error:', err.message);
    }
  };
  tick();
  return setInterval(tick, intervalMs);
}

module.exports = { startIngestor, processNewData };
