'use strict';

// Runs every declarative rule (rules.js) over one event via the shared EQL
// engine, returning zero or more alerts (an event can match multiple rules).
// A rule whose query fails to evaluate is logged and skipped rather than
// aborting the whole pass.

const EQL = require('../../dashboard/js/eql.js');
const { techniqueName } = require('./mitre');
const RULES = require('./rules');

function matchEvent(evt) {
  const alerts = [];
  for (const rule of RULES) {
    let hit;
    try {
      hit = EQL.matches(rule.query, evt);
    } catch (err) {
      console.error(`[detection] rule '${rule.name}' query error:`, err.message);
      continue;
    }
    if (hit) {
      alerts.push({
        ts: evt.timestamp,
        severity: rule.severity,
        mitreId: rule.mitreId,
        mitreName: techniqueName(rule.mitreId),
        ruleName: rule.name,
        title: rule.title,
        detail: (evt.process?.cmdline || evt.process?.path || '').slice(0, 200),
      });
    }
  }
  return alerts;
}

module.exports = { matchEvent };
