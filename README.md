# reaperwatch

EDR for Windows. Built to learn, built to detect.

ReaperWatch is a from-scratch Windows EDR (Endpoint Detection and Response) tool: a userland
agent that captures process telemetry via ETW, enriches it with everything an analyst would want
to know about a process, and a console (storage + detection engine + dashboard) to hunt through
that telemetry and surface alerts. Built incrementally, one real Windows mechanism at a time.

## Status

**Concept 1 — Process Telemetry Collector: complete.** The agent captures every process launch on
the machine in real time and emits a fully enriched, normalized event. The console ingests that
telemetry, runs it through a declarative detection engine, and presents it in a live dashboard.

Download a prebuilt, dependency-free agent from the
[latest release](https://github.com/aadilvarshani/reaperwatch/releases/latest).

## Architecture

```
agent/            C++ userland sensor
  collectors/       process telemetry: acquisition + enrichment
  transport/        durable event sink (JSONL)
  detections/       native detection engine (placeholder, Phase 2+)
engine/           native rule matcher (placeholder, Phase 2+)
driver/           kernel-mode minifilter (placeholder, Phase 2)

backend/          Node.js console backend
  storage/          SQLite schema + connection (built-in node:sqlite)
  ingestor/         tails the agent's JSONL log into SQLite
  detection/        EQL-based rule engine
  api/              Express API serving the dashboard + data

dashboard/        browser console (Overview / Detections / Hunt)
  js/eql.js         shared query engine (used by Hunt AND detection rules)

third_party/      vendored dependencies (nlohmann/json)
.github/workflows/  CI: builds + publishes the agent as a GitHub Release
```

## Features

### Agent (C++, `agent/`)

- **Live acquisition** via ETW — the NT Kernel Logger (`EVENT_TRACE_FLAG_PROCESS`), catching every
  process creation on the machine as it happens.
- **Full enrichment**, per event:
  - Image path and full command line (read from the target process's PEB)
  - Parent and grandparent process lineage, with a PID-reuse guard so a recycled PID never gets
    attributed to the wrong parent
  - User context: account, domain, SID, admin/SYSTEM privilege flags
  - SHA256 and MD5, streamed via CNG (constant memory regardless of file size)
  - Authenticode signature verification — both embedded signatures and the system-catalog path
    (covers OS binaries like `notepad.exe` that have no embedded signature), plus signer identity
  - Host context: hostname, true OS version (not the lying `GetVersionEx`), architecture
- **Durable transport** — every event is appended as a JSON line to `data/events.jsonl`
  (`agent/transport/`), independent of whether anything is currently consuming it.
- **Zero-dependency Release build** — statically linked MSVC runtime, so the shipped `.exe` needs
  nothing but Windows itself (no VC++ Redistributable) and Administrator rights.

### Console backend (Node.js, `backend/`)

- **Storage** — SQLite (Node's built-in `node:sqlite`, no native dependency to compile) with the
  full enriched event shape plus a `raw_json` column for drill-down.
- **Ingestor** — tails `events.jsonl` by byte offset; resilient to partial writes (the agent mid
  write) and corrupt lines (skipped and logged, never blocks subsequent events).
- **Detection engine** — rules are declarative data, not code: a query string plus severity and a
  MITRE ATT&CK technique ID (`backend/detection/rules.js`). Adding a detection means adding one
  entry, not writing a function.
- **API** — Express endpoints for the dashboard: overview stats, event search, alerts, host info.

### Query language (`dashboard/js/eql.js`)

A scoped subset of Elastic's Event Query Language (EQL), implemented once and shared by both the
Hunt view (ad-hoc search) and the detection engine (declarative rules), so there's one grammar to
learn and one interpreter to trust.

```
process where wildcard(process.name, "*powershell*")
          and match(process.cmdline, "-e(nc(odedcommand)?)?\\b")
```

Supported: `==` `!=` `<` `<=` `>` `>=`, `in (...)`, `and`/`or`/`not`, parentheses, and the functions
`wildcard()`, `match()` (regex), `startsWith()`, `endsWith()`, `length()`. Not yet implemented:
sequence/join queries and additional event types beyond `process`/`any` — noted in the roadmap.

### Dashboard (`dashboard/`)

- **Overview** — stat cards, 7-day detection volume, MITRE tactic breakdown, live activity feed,
  fleet health.
- **Detections** — every alert the rule engine has fired, filterable by severity.
- **Hunt** — free-form EQL search over raw telemetry, with full-JSON drill-down per event.
- Falls back to bundled sample data (with a visible banner) if the backend isn't reachable, so the
  UI is always inspectable even without a running agent.

## Getting started

### Build the agent

Requires Visual Studio Build Tools (MSVC + Windows SDK), CMake, and Ninja — build from a
"Developer PowerShell for VS 2022":

```powershell
cmake -S . -B build -G Ninja
cmake --build build
.\build\agent\reaperwatch_agent.exe   # run as Administrator
```

### Run the console

```powershell
cd backend
npm install
npm start   # http://localhost:3000
```

The console tails `data/events.jsonl` automatically — start the agent (as Administrator) and
watch events and detections appear live.

## Detection rules

Rules live in [`backend/detection/rules.js`](backend/detection/rules.js). Current coverage:
encoded PowerShell, `certutil` remote downloads, common LOLBins (`rundll32`, `regsvr32`, `mshta`,
script hosts, `bitsadmin`, `installutil`), Office-spawned shells, unsigned binaries executing from
`Temp`/`Downloads`, and unexpected SYSTEM shells — each mapped to a MITRE ATT&CK technique.

## Lab deployment

The agent is the only piece that needs to run on a test/victim VM — copy the standalone `.exe`
from a [release](https://github.com/aadilvarshani/reaperwatch/releases), run it as Administrator,
and copy `data/events.jsonl` back to a machine running the console to review results. CI publishes
a fresh build on every push and cuts a release on every `v*` tag.

## Roadmap

- **Parent enrichment** — lineage currently only fills the parent's pid/name; reuse the existing
  path/hash/signature functions on `parent.pid` for full parity with the subject process.
- **Async enrichment** — the ETW callback enriches synchronously; move to a lock-free queue with
  worker threads so a slow hash never blocks the next event.
- **Tri-state signature field** — `is_signed` currently can't distinguish "verified unsigned" from
  "couldn't check" (process exited before enrichment); needs to become a three-state value.
- **Kernel driver (Phase 2)** — `PsSetCreateProcessNotifyRoutineEx2`, becoming the primary
  acquisition source: earlier visibility than ETW, and the ability to block a process outright.
  Fixes the short-lived-process visibility gap inherent to userland acquisition.
- **More collectors** — file, network, and registry telemetry, following the same
  acquisition-then-enrichment pattern established for process events.
- **OCSF schema adoption** — migrate the event model to the Open Cybersecurity Schema Framework's
  Process Activity class for interoperability with other security tooling. A deliberate, dedicated
  effort (touches the agent's serializer, the SQL schema, every detection rule, and the dashboard),
  not bundled in with unrelated work.
- **EQL sequences** — multi-stage detection (e.g. `sequence by host [...] [...]`) for attack chains
  spanning more than one event, beyond the current single-event `where` clauses.
