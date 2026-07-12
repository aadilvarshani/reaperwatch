'use strict';

// One shared "store this event, run detections, store any alerts" path used
// by BOTH the file-tailing ingestor (tail.js, for copied-in JSONL files) and
// the live HTTP endpoint (api/server.js POST /api/ingest) -- one insert path,
// not two copies that could drift apart.

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

function isValidEvent(evt) {
  return !!evt && typeof evt === 'object' && typeof evt.event_type === 'string' && !!evt.process;
}

// Store one event, run detections against it, store any alerts.
// Returns { eventId, alerts }. Throws if `evt` doesn't look like a real event.
function ingestEvent(db, matchEvent, evt) {
  if (!isValidEvent(evt)) {
    throw new Error('event missing required fields (event_type, process)');
  }
  const eventId = insertEvent(db, evt);
  const alerts = matchEvent(evt);
  for (const alert of alerts) insertAlert(db, eventId, alert);
  return { eventId, alerts };
}

module.exports = { ingestEvent, insertEvent, insertAlert, isValidEvent };
