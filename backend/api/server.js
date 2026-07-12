'use strict';

const express = require('express');
const path = require('node:path');

const { openDb } = require('../storage/db');
const { loadOrCreateIngestKey } = require('../storage/ingestKey');
const { startIngestor } = require('../ingestor/tail');
const { ingestEvent } = require('../ingestor/ingest');
const { matchEvent } = require('../detection/matcher');
const queries = require('./queries');

const PORT = process.env.PORT || 3000;
const DASHBOARD_DIR = path.join(__dirname, '..', '..', 'dashboard');

const db = openDb();
startIngestor(db, matchEvent, { intervalMs: 1000 });

const INGEST_KEY = loadOrCreateIngestKey();
console.log(`Ingest key (put this in an agent's reaperwatch.config.json to allow it to send events here): ${INGEST_KEY}`);

const app = express();
app.use(express.static(DASHBOARD_DIR));

app.get('/api/overview', (req, res) => {
  res.json(queries.getOverview(db));
});

app.get('/api/events', (req, res) => {
  const { event_type, limit } = req.query;
  res.json(queries.listEvents(db, {
    eventType: event_type,
    limit: limit ? Number(limit) : undefined,
  }));
});

app.get('/api/events/:id', (req, res) => {
  const evt = queries.getEventById(db, Number(req.params.id));
  if (!evt) return res.status(404).json({ error: 'not found' });
  res.json(evt);
});

app.get('/api/alerts', (req, res) => {
  const { severity, mitre, limit } = req.query;
  res.json(queries.listAlerts(db, {
    severity, mitreId: mitre,
    limit: limit ? Number(limit) : undefined,
  }));
});

app.get('/api/host', (req, res) => {
  res.json(queries.getHost(db));
});

// Live ingestion from a remote agent. Requires the exact local ingest key --
// this is the entire isolation mechanism: no key, no acceptance, regardless
// of where the request came from.
app.post('/api/ingest', express.json({ limit: '256kb' }), (req, res) => {
  if (req.get('X-ReaperWatch-Key') !== INGEST_KEY) {
    return res.status(401).json({ error: 'invalid or missing key' });
  }
  try {
    const { eventId, alerts } = ingestEvent(db, matchEvent, req.body);
    res.status(202).json({ ok: true, id: eventId, alerts: alerts.length });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`ReaperWatch console listening on http://localhost:${PORT}`);
});
