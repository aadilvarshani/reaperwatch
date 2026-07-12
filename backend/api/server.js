'use strict';

const express = require('express');
const path = require('node:path');

const { openDb } = require('../storage/db');
const { startIngestor } = require('../ingestor/tail');
const { matchEvent } = require('../detection/matcher');
const queries = require('./queries');

const PORT = process.env.PORT || 3000;
const DASHBOARD_DIR = path.join(__dirname, '..', '..', 'dashboard');

const db = openDb();
startIngestor(db, matchEvent, { intervalMs: 1000 });

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

app.listen(PORT, () => {
  console.log(`ReaperWatch console listening on http://localhost:${PORT}`);
});
