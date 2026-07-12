'use strict';

// The local secret an agent must present (X-ReaperWatch-Key) for its events
// to be accepted. Generated once per console install and persisted locally
// (never committed, never hardcoded) -- this is what keeps independently-run
// agent/console pairs from ever cross-talking: without this exact value, the
// console rejects the event outright.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DATA_DIR } = require('./db');

const KEY_FILE = path.join(DATA_DIR, 'ingest.key');

function loadOrCreateIngestKey() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  if (fs.existsSync(KEY_FILE)) {
    return fs.readFileSync(KEY_FILE, 'utf8').trim();
  }
  const key = crypto.randomBytes(24).toString('hex');
  fs.writeFileSync(KEY_FILE, key, { mode: 0o600 });
  return key;
}

module.exports = { loadOrCreateIngestKey, KEY_FILE };
