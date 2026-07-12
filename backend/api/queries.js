'use strict';

// Read-side SQL for the dashboard API. Kept separate from server.js/routing so
// it can be tested directly against a database without spinning up HTTP.

const { techniqueTactic } = require('../detection/mitre');

const TACTIC_COLORS = {
  'Execution': '#e5484d',
  'Defense Evasion': '#f5a524',
  'Privilege Escalation': '#f3d13e',
  'Command and Control': '#4a90e2',
  'Persistence': '#4a90e2',
  'Discovery': '#8b90a0',
  'Uncategorized': '#8b90a0',
};

function delta(curr, prev) {
  const diff = curr - prev;
  return { delta: (diff >= 0 ? '+' : '') + diff, dir: diff > 0 ? 'up' : diff < 0 ? 'down' : 'flat' };
}

function getOverview(db) {
  const now = Date.now();
  const since24h = new Date(now - 24 * 3600 * 1000).toISOString();
  const since48h = new Date(now - 48 * 3600 * 1000).toISOString();

  const count = (sql, ...params) => db.prepare(sql).get(...params).c;

  const events24h = count('SELECT COUNT(*) c FROM events WHERE ts >= ?', since24h);
  const eventsPrev24h = count('SELECT COUNT(*) c FROM events WHERE ts >= ? AND ts < ?', since48h, since24h);

  const openDetections = count('SELECT COUNT(*) c FROM alerts');
  const detections24h = count(
    'SELECT COUNT(*) c FROM alerts a JOIN events e ON e.id = a.event_id WHERE e.ts >= ?', since24h);
  const detectionsPrev24h = count(
    'SELECT COUNT(*) c FROM alerts a JOIN events e ON e.id = a.event_id WHERE e.ts >= ? AND e.ts < ?',
    since48h, since24h);

  const unsigned24h = count('SELECT COUNT(*) c FROM events WHERE ts >= ? AND proc_signed = 0', since24h);
  const unsignedPrev24h = count(
    'SELECT COUNT(*) c FROM events WHERE ts >= ? AND ts < ? AND proc_signed = 0', since48h, since24h);

  const lolbin24h = count('SELECT COUNT(*) c FROM events WHERE ts >= ? AND flag_is_lolbin = 1', since24h);
  const lolbinPrev24h = count(
    'SELECT COUNT(*) c FROM events WHERE ts >= ? AND ts < ? AND flag_is_lolbin = 1', since48h, since24h);

  // 7-day detection volume by day + severity.
  const days = [];
  for (let i = 6; i >= 0; i--) days.push(new Date(now - i * 24 * 3600 * 1000).toISOString().slice(0, 10));
  const windowStart = days[0] + 'T00:00:00.000Z';
  const volumeRows = db.prepare(`
    SELECT substr(e.ts, 1, 10) AS day, a.severity AS severity, COUNT(*) AS c
    FROM alerts a JOIN events e ON e.id = a.event_id
    WHERE e.ts >= ?
    GROUP BY day, severity
  `).all(windowStart);
  const volume = { days, critical: days.map(() => 0), high: days.map(() => 0), medlow: days.map(() => 0) };
  for (const row of volumeRows) {
    const idx = days.indexOf(row.day);
    if (idx === -1) continue;
    if (row.severity === 'critical') volume.critical[idx] += row.c;
    else if (row.severity === 'high') volume.high[idx] += row.c;
    else volume.medlow[idx] += row.c;
  }

  // Alert breakdown by MITRE tactic.
  const mitreRows = db.prepare('SELECT mitre_id, COUNT(*) AS c FROM alerts GROUP BY mitre_id').all();
  const tacticCounts = new Map();
  for (const row of mitreRows) {
    const tactic = techniqueTactic(row.mitre_id);
    tacticCounts.set(tactic, (tacticCounts.get(tactic) || 0) + row.c);
  }
  const items = [...tacticCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, value]) => ({ name, value, color: TACTIC_COLORS[name] || '#8b90a0' }));
  const total = items.reduce((s, it) => s + it.value, 0);

  return {
    stats: [
      { label: 'PROCESS EVENTS (24H)', value: events24h, ...delta(events24h, eventsPrev24h) },
      { label: 'OPEN DETECTIONS', value: openDetections, ...delta(detections24h, detectionsPrev24h) },
      { label: 'UNSIGNED EXECUTIONS', value: unsigned24h, ...delta(unsigned24h, unsignedPrev24h) },
      { label: 'LOLBIN LAUNCHES', value: lolbin24h, ...delta(lolbin24h, lolbinPrev24h) },
    ],
    volume,
    breakdown: { total, items },
  };
}

function listEvents(db, { eventType, limit = 500 } = {}) {
  let sql = 'SELECT id, raw_json FROM events';
  const params = [];
  if (eventType) { sql += ' WHERE event_type = ?'; params.push(eventType); }
  sql += ' ORDER BY id DESC LIMIT ?';
  params.push(Math.min(limit, 5000));
  return db.prepare(sql).all(...params).map(r => ({ id: r.id, ...JSON.parse(r.raw_json) }));
}

function getEventById(db, id) {
  const row = db.prepare('SELECT id, raw_json FROM events WHERE id = ?').get(id);
  return row ? { id: row.id, ...JSON.parse(row.raw_json) } : null;
}

function listAlerts(db, { severity, mitreId, limit = 200 } = {}) {
  let sql = `
    SELECT a.id, a.event_id, a.ts, a.severity, a.mitre_id, a.mitre_name, a.rule_name, a.title, a.detail,
           e.proc_name, e.proc_pid, e.user_name, e.host_hostname
    FROM alerts a JOIN events e ON e.id = a.event_id
    WHERE 1=1
  `;
  const params = [];
  if (severity) { sql += ' AND a.severity = ?'; params.push(severity); }
  if (mitreId) { sql += ' AND a.mitre_id = ?'; params.push(mitreId); }
  sql += ' ORDER BY a.id DESC LIMIT ?';
  params.push(Math.min(limit, 5000));
  return db.prepare(sql).all(...params);
}

function getHost(db) {
  const row = db.prepare(
    'SELECT host_hostname, host_os, host_arch FROM events ORDER BY id DESC LIMIT 1').get();
  return row
    ? { hostname: row.host_hostname, os: row.host_os, arch: row.host_arch, online: true }
    : { hostname: null, os: null, arch: null, online: false };
}

module.exports = { getOverview, listEvents, getEventById, listAlerts, getHost };
