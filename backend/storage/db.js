'use strict';

// Opens (creating if needed) the ReaperWatch SQLite database and applies the
// schema. Uses Node's built-in node:sqlite (DatabaseSync) -- no native
// dependency to install or compile.

const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

// Overridable so tests (and alternate deployments) never have to touch the
// real machine's live telemetry directory.
const DATA_DIR = process.env.REAPERWATCH_DATA_DIR || 'C:\\ReaperWatch\\data';
const DB_PATH = path.join(DATA_DIR, 'reaperwatch.db');
const EVENTS_FILE = path.join(DATA_DIR, 'events.jsonl');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

function openDb() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const db = new DatabaseSync(DB_PATH);
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));
  return db;
}

module.exports = { openDb, DATA_DIR, DB_PATH, EVENTS_FILE };
