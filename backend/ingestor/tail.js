'use strict';

// Tails data/events.jsonl: on each tick, reads only the bytes appended since
// the last read (tracked in ingest_state), parses each complete line as one
// event, and hands it to the shared ingest path (ingest.js).

const fs = require('node:fs');
const { EVENTS_FILE } = require('../storage/db');
const { ingestEvent } = require('./ingest');

function getOffset(db) {
  const row = db.prepare('SELECT byte_offset FROM ingest_state WHERE id = 1').get();
  return row ? row.byte_offset : 0;
}

function setOffset(db, offset) {
  db.prepare('UPDATE ingest_state SET byte_offset = ? WHERE id = 1').run(offset);
}

// Reads and processes whatever is new in events.jsonl since the last call.
// Returns the number of events ingested.
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
      ingestEvent(db, matchEvent, evt);
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
      if (n > 0) console.log(`[ingestor] ingested ${n} event(s) from events.jsonl`);
    } catch (err) {
      console.error('[ingestor] error:', err.message);
    }
  };
  tick();
  return setInterval(tick, intervalMs);
}

module.exports = { startIngestor, processNewData };
