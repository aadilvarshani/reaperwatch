/*
 * ReaperWatch console — rendering + interactions.
 *
 * Renders immediately from the bundled sample data (window.RW, from data.js)
 * for a fast first paint, then tries the live API. If the backend answers,
 * DATA is replaced with real telemetry and everything re-renders; if not, the
 * sample data stays up and a "DEMO DATA" banner makes that unambiguous. A
 * live connection is polled periodically to keep the console current.
 */
const DATA = window.RW;
const $ = (s, r = document) => r.querySelector(s);
const el = (t, cls, html) => { const e = document.createElement(t); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
const esc = s => String(s).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const REFRESH_MS = 5000;
let currentFeedFilter = "all";
let currentSevFilter = "all";
let huntHasSelection = false;

document.addEventListener("DOMContentLoaded", () => {
  renderAll();
  wireNav();
  wireControls();
  startClock();
  refreshFromApi();
  setInterval(refreshFromApi, REFRESH_MS);
});

function renderAll() {
  renderStats();
  renderVolume();
  renderDonut();
  renderFeed(currentFeedFilter);
  renderFleet();
  renderTopSigners();
  renderDetections(currentSevFilter);
  renderHuntExamples();
  renderHunt({ resetDetail: false });
  $("#overviewSub").innerHTML =
    `Sensor active on <b>1</b> endpoint · <b>${DATA.host.hostname}</b> · ${DATA.host.os}`;
}

/* ------------------------------ live data ------------------------------ */
async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return res.json();
}

function iconFor(label) {
  if (label.includes("PROCESS EVENTS")) return "◎";
  if (label.includes("OPEN DETECTIONS")) return "⚠";
  if (label.includes("UNSIGNED")) return "✎";
  if (label.includes("LOLBIN")) return "⌘";
  return "◎";
}

// API alert shape -> the shape renderFeed/renderDetections expect.
function adaptAlert(a) {
  return {
    sev: a.severity, rule: a.title, proc: a.proc_name, pid: a.proc_pid,
    mitre: a.mitre_id, mitreName: a.mitre_name, user: a.user_name,
    time: (a.ts || "").slice(11, 19), detail: a.detail, host: a.host_hostname,
  };
}

function addDisplayTime(e) {
  return { ...e, time: (e.timestamp || "").slice(11, 19) };
}

function computeTopSigners(events) {
  const counts = new Map();
  for (const e of events) {
    const key = e.process?.signed ? (e.process.signer || "Unknown") : "(unsigned)";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1]).slice(0, 6)
    .map(([name, value]) => ({ name, value: String(value), color: name === "(unsigned)" ? "#e5484d" : "#4a90e2" }));
}

async function refreshFromApi() {
  try {
    const [overview, events, alerts, host] = await Promise.all([
      fetchJSON("/api/overview"),
      fetchJSON("/api/events?limit=2000"),
      fetchJSON("/api/alerts?limit=500"),
      fetchJSON("/api/host"),
    ]);

    DATA.stats = overview.stats.map(s => ({ ...s, ico: iconFor(s.label), spark: [] }));
    DATA.volume = overview.volume;
    DATA.breakdown = overview.breakdown;
    DATA.events = events.map(addDisplayTime);
    DATA.detections = alerts.map(adaptAlert);
    if (host.hostname) DATA.host = host;
    DATA.topSigners = computeTopSigners(events);

    setDemoBanner(false);
    renderAll();
  } catch (err) {
    // Backend not reachable (or not running yet) -- keep showing whatever
    // DATA currently holds (sample data, or the last good live snapshot) and
    // make it unmistakable that it isn't fresh live telemetry.
    console.warn("[dashboard] live refresh failed:", err.message);
    setDemoBanner(true);
  }
}

function setDemoBanner(show) {
  const b = $("#demoBanner");
  if (b) b.hidden = !show;
}

/* ----------------------------- navigation ----------------------------- */
function wireNav() {
  document.querySelectorAll(".nav-item[data-view]").forEach(item => {
    item.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach(n => n.classList.remove("active"));
      item.classList.add("active");
      const view = item.dataset.view;
      document.querySelectorAll(".view").forEach(v => v.hidden = true);
      $("#view-" + view).hidden = false;
    });
  });
}

function wireControls() {
  document.querySelectorAll("[data-feed]").forEach(s => s.addEventListener("click", e => {
    document.querySelectorAll("[data-feed]").forEach(x => x.classList.remove("active"));
    e.target.classList.add("active");
    currentFeedFilter = e.target.dataset.feed;
    renderFeed(currentFeedFilter);
  }));
  document.querySelectorAll("#sevChips .chip").forEach(c => c.addEventListener("click", e => {
    document.querySelectorAll("#sevChips .chip").forEach(x => x.classList.remove("active"));
    e.target.classList.add("active");
    currentSevFilter = e.target.dataset.sev;
    renderDetections(currentSevFilter);
  }));
  $("#huntRun").addEventListener("click", () => renderHunt());
  $("#huntQuery").addEventListener("keydown", e => { if (e.key === "Enter") renderHunt(); });
  $("#refreshBtn").addEventListener("click", () => {
    $("#refreshBtn").style.transform = "rotate(360deg)";
    setTimeout(() => $("#refreshBtn").style.transform = "", 400);
    refreshFromApi();
  });
}

/* ----------------------------- stat cards ----------------------------- */
function renderStats() {
  const g = $("#statGrid");
  g.innerHTML = "";  // clear first: this runs on every refresh, not just once
  DATA.stats.forEach(s => {
    const c = el("div", "stat-card");
    c.innerHTML = `
      <div class="st-head"><span class="st-label">${s.label}</span><span class="st-ico">${s.ico}</span></div>
      <div class="st-value">${s.value}</div>
      <div class="st-delta ${s.dir}">${s.dir === "up" ? "▲" : s.dir === "down" ? "▼" : "■"} ${s.delta} vs. yesterday</div>
      ${sparkline(s.spark, s.dir)}`;
    g.appendChild(c);
  });
}
function sparkline(arr, dir) {
  const w = 84, h = 30;
  if (!arr || arr.length < 2) {
    return `<svg class="st-spark" viewBox="0 0 ${w} ${h}"><line x1="0" y1="${h - 1}" x2="${w}" y2="${h - 1}" stroke="#2c303a" stroke-width="1.5"/></svg>`;
  }
  const max = Math.max(...arr), min = Math.min(...arr), rng = max - min || 1;
  const pts = arr.map((v, i) => `${(i / (arr.length - 1) * w).toFixed(1)},${(h - (v - min) / rng * h).toFixed(1)}`).join(" ");
  const col = dir === "down" ? "#e5484d" : "#3fb950";
  return `<svg class="st-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">
    <polyline points="${pts}" fill="none" stroke="${col}" stroke-width="1.5" stroke-linejoin="round" opacity="0.9"/></svg>`;
}

/* -------------------------- volume area chart -------------------------- */
function renderVolume() {
  const v = DATA.volume, n = v.days.length;
  const W = 620, H = 190, padL = 26, padB = 22, padT = 8;
  const plotW = W - padL - 8, plotH = H - padT - padB;
  const totals = v.days.map((_, i) => v.critical[i] + v.high[i] + v.medlow[i]);
  const max = Math.max(...totals, 1) * 1.15;
  const x = i => padL + (n > 1 ? (i / (n - 1)) * plotW : plotW / 2);
  const y = val => padT + plotH * (1 - val / max);

  // cumulative stacks (critical bottom → high → medlow top)
  const c1 = v.critical;
  const c2 = v.days.map((_, i) => v.critical[i] + v.high[i]);
  const c3 = totals;
  const zero = v.days.map(() => 0);

  const legend = [
    { name: "Critical", color: "#e5484d" },
    { name: "High", color: "#f5a524" },
    { name: "Med/Low", color: "#6b7280" },
  ];
  $("#volumeLegend").innerHTML = legend.map(l =>
    `<span class="leg"><span class="sw" style="background:${l.color}"></span>${l.name}</span>`).join("");

  const band = (lower, upper, color, op) => {
    let d = "M" + upper.map((val, i) => `${x(i)},${y(val)}`).join(" L");
    for (let i = lower.length - 1; i >= 0; i--) d += ` L${x(i)},${y(lower[i])}`;
    d += " Z";
    const line = "M" + upper.map((val, i) => `${x(i)},${y(val)}`).join(" L");
    return `<path d="${d}" fill="${color}" opacity="${op}"/><path d="${line}" fill="none" stroke="${color}" stroke-width="1.5"/>`;
  };

  // gridlines + y labels
  let grid = "";
  for (let g = 0; g <= 3; g++) {
    const val = Math.round(max / 3 * g), gy = y(val);
    grid += `<line x1="${padL}" y1="${gy}" x2="${W - 8}" y2="${gy}" stroke="#20232a" stroke-width="1"/>
             <text class="axis" x="${padL - 6}" y="${gy + 3}" text-anchor="end">${val}</text>`;
  }
  const xlabels = v.days.map((d, i) => `<text class="axis" x="${x(i)}" y="${H - 6}" text-anchor="middle">${d.slice(5)}</text>`).join("");

  $("#volumeChart").innerHTML = `<svg viewBox="0 0 ${W} ${H}">
    ${grid}
    ${band(zero, c3, "#6b7280", 0.18)}
    ${band(zero, c2, "#f5a524", 0.20)}
    ${band(zero, c1, "#e5484d", 0.30)}
    ${xlabels}
  </svg>`;
}

/* ------------------------------- donut ------------------------------- */
function renderDonut() {
  const b = DATA.breakdown, R = 62, sw = 14, C = 2 * Math.PI * R, size = 150;
  if (!b.total) {
    $("#donutChart").innerHTML = `
      <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
        <circle cx="${size / 2}" cy="${size / 2}" r="${R}" fill="none" stroke="#1c1f26" stroke-width="${sw}"/>
      </svg>
      <div class="donut-center"><div><div class="dc-num">0</div><div class="dc-lbl">TOTAL</div></div></div>`;
    $("#donutLegend").innerHTML = `<div class="dleg"><span class="dl-name muted">No detections yet.</span></div>`;
    return;
  }
  let offset = 0;
  const segs = b.items.map(it => {
    const frac = it.value / b.total, len = frac * C;
    const s = `<circle cx="${size / 2}" cy="${size / 2}" r="${R}" fill="none"
      stroke="${it.color}" stroke-width="${sw}" stroke-linecap="butt"
      stroke-dasharray="${len} ${C - len}" stroke-dashoffset="${-offset}"
      transform="rotate(-90 ${size / 2} ${size / 2})"/>`;
    offset += len; return s;
  }).join("");
  $("#donutChart").innerHTML = `
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
      <circle cx="${size / 2}" cy="${size / 2}" r="${R}" fill="none" stroke="#1c1f26" stroke-width="${sw}"/>
      ${segs}
    </svg>
    <div class="donut-center"><div><div class="dc-num">${b.total}</div><div class="dc-lbl">TOTAL</div></div></div>`;
  const max = Math.max(...b.items.map(i => i.value));
  $("#donutLegend").innerHTML = b.items.map(it => `
    <div class="dleg">
      <span class="sw" style="background:${it.color}"></span>
      <span class="dl-name">${it.name}</span>
      <span class="dl-bar"><span style="width:${it.value / max * 100}%;background:${it.color}"></span></span>
      <span class="dl-val">${it.value}</span>
    </div>`).join("");
}

/* --------------------------- live activity feed --------------------------- */
function renderFeed(filter) {
  const rows = DATA.detections.filter(d => filter === "all" || d.sev === "critical").slice(0, 20);
  $("#feedBody").innerHTML = rows.map(d => `
    <tr>
      <td><span class="sev-chip sev-${d.sev}">${d.sev[0].toUpperCase()}</span></td>
      <td class="host-proc"><div class="hp-host">${d.host || ""}</div><div class="hp-proc">${d.proc} [PID: ${d.pid}]</div></td>
      <td><div class="det-text">${d.rule}</div><div class="det-sub">${esc(d.detail || "")}</div></td>
      <td><span class="mitre">${d.mitre}</span></td>
      <td class="time">${d.time}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="muted" style="text-align:center;padding:28px">No activity yet.</td></tr>`;
}

/* ------------------------------ fleet health ------------------------------ */
function renderFleet() {
  const h = DATA.host;
  $("#fleet").innerHTML = `
    <div class="fleet-row">
      <div class="fr-top"><span class="fr-name">🖥 Windows</span>
        <span><span class="fr-count">${h.online === false ? 0 : 1}</span><span class="fr-pct">${h.online === false ? "" : "100%"}</span></span></div>
      <div class="fr-bar"><span style="width:${h.online === false ? 0 : 100}%"></span></div>
      <div class="fr-sub">${h.hostname || "waiting for telemetry..."} ${h.os ? "· " + h.os : ""} ${h.arch ? "· " + h.arch : ""}</div>
    </div>
    <div class="fleet-row" style="opacity:.45">
      <div class="fr-top"><span class="fr-name">🐧 Linux</span><span class="fr-count">0</span></div>
      <div class="fr-bar"><span style="width:0"></span></div>
      <div class="fr-sub">no sensors deployed</div>
    </div>
    <div class="fleet-row" style="opacity:.45">
      <div class="fr-top"><span class="fr-name">🍎 macOS</span><span class="fr-count">0</span></div>
      <div class="fr-bar"><span style="width:0"></span></div>
      <div class="fr-sub">no sensors deployed</div>
    </div>`;
}
function renderTopSigners() {
  $("#topSigners").innerHTML = DATA.topSigners.map(s => `
    <div class="top-row">
      <span class="tr-dot" style="background:${s.color}"></span>
      <span class="tr-name">${s.name}</span>
      <span class="tr-val">${s.value}</span>
    </div>`).join("") || `<div class="muted" style="padding:8px 4px">No data yet.</div>`;
}

/* ------------------------------ detections ------------------------------ */
function renderDetections(sev) {
  const rows = DATA.detections.filter(d => sev === "all" || d.sev === sev);
  $("#detBody").innerHTML = rows.map(d => `
    <tr>
      <td><span class="sev-chip sev-${d.sev}">${d.sev[0].toUpperCase()}</span></td>
      <td><div class="det-text">${d.rule}</div><div class="det-sub">${esc(d.detail || "")}</div></td>
      <td class="mono">${d.proc} <span class="muted">[${d.pid}]</span></td>
      <td><span class="mitre">${d.mitre}</span> <span class="muted">${d.mitreName || ""}</span></td>
      <td class="mono">${d.user}</td>
      <td class="time">${d.time}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted" style="text-align:center;padding:28px">No detections at this severity.</td></tr>`;
}

/* --------------------------------- hunt --------------------------------- */
const HUNT_EXAMPLES = [
  'process where true',
  'process where process.signed == false',
  'process where match(process.cmdline, "-e(nc(odedcommand)?)?\\\\b")',
  'process where user.is_system == true and not parent.name in ("services.exe", "svchost.exe")',
];

function renderHuntExamples() {
  $("#huntExamples").innerHTML = HUNT_EXAMPLES.map(q => `<span class="ex-chip">${esc(q)}</span>`).join("");
  document.querySelectorAll(".ex-chip").forEach(chip => chip.addEventListener("click", () => {
    $("#huntQuery").value = chip.textContent;
    renderHunt();
  }));
}

// resetDetail=false is used for silent periodic refreshes, so an operator
// reading a selected event's JSON doesn't get yanked back to the empty state
// every 5 seconds. Explicit user actions (Run, Enter, example chip) reset it.
function renderHunt({ resetDetail = true } = {}) {
  const src = $("#huntQuery").value.trim();
  const status = $("#huntStatus");
  let rows;
  try {
    rows = window.RWEQL.runQuery(src, DATA.events);
    status.className = "hunt-status ok";
    status.textContent = `${rows.length} event${rows.length === 1 ? "" : "s"} matched`;
  } catch (e) {
    status.className = "hunt-status err";
    status.textContent = "⚠ " + e.message;
    rows = [];
  }

  $("#huntBody").innerHTML = rows.map((e, i) => `
    <tr data-i="${i}">
      <td class="time">${e.time}</td>
      <td class="mono">${e.process.name}${e.process.signed ? "" : ' <span style="color:var(--crit)">●</span>'}</td>
      <td class="mono muted">${e.process.pid}</td>
      <td class="mono muted">${e.process.signer || "(unsigned)"}</td>
      <td class="mono">${e.user.name}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="muted" style="text-align:center;padding:28px">No matching events.</td></tr>`;

  document.querySelectorAll("#huntBody tr[data-i]").forEach(tr => tr.addEventListener("click", () => {
    document.querySelectorAll("#huntBody tr").forEach(x => x.classList.remove("sel"));
    tr.classList.add("sel");
    huntHasSelection = true;
    $("#huntDetail").innerHTML = "<pre>" + jsonHi(rows[+tr.dataset.i]) + "</pre>";
  }));

  if (resetDetail) {
    huntHasSelection = false;
    $("#huntDetail").innerHTML = `<div class="empty">Select a result to inspect its full JSON.</div>`;
  }
}
function jsonHi(obj) {
  const clean = { ...obj }; delete clean.time;
  return esc(JSON.stringify(clean, null, 2))
    .replace(/&quot;([^&]+)&quot;(\s*:)/g, '<span class="j-key">"$1"</span>$2')
    .replace(/:\s&quot;([^&]*)&quot;/g, ': <span class="j-str">"$1"</span>')
    .replace(/:\s(-?\d+\.?\d*)/g, ': <span class="j-num">$1</span>')
    .replace(/:\s(true|false)/g, ': <span class="j-bool">$1</span>')
    .replace(/:\s(null)/g, ': <span class="j-null">$1</span>');
}

/* --------------------------------- clock --------------------------------- */
function startClock() {
  const tick = () => { $("#clock").textContent = new Date().toISOString().slice(11, 19); };
  tick(); setInterval(tick, 1000);
}
