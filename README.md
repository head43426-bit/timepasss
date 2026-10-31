# ASK - Analyse Secure Kill
## Kill Chain Attack Path Reconstruction

Turn your security logs into one attack story: where it began,
what the attacker did, and what they can reach next.

Branding: the logo lives in `assets/` with a transparent background
(`ask-logo.png`, plus `ask-logo-light.png` with white text for dark
headers), animated with a gentle float + flame flicker in the /app
header and the showcase topbar. Favicons: `favicon.ico` (16/32/48),
`favicon-16.png`, `favicon-32.png`, `favicon-48.png`,
`apple-touch-icon.png`, `icon-192.png`, `icon-512.png`, and
`site.webmanifest`. Note: the snapshot push used for this repo accepts
UTF-8 text only, so binary PNG/ICO files cannot be pushed directly -
each one also has a `.b64` text twin in `assets/`, and `main.py`
decodes that twin and serves the exact original bytes when the binary
is missing after a pull (verified byte-identical).

**No demo data in this project.** You bring your own `.log` file.
Use only synthetic or authorised logs - never real production
logs or credentials.

## Run it

```bash
pip install -r requirements.txt
python main.py serve --db out.duckdb --port 8001
# open http://localhost:8001 - the showcase is the main page
# click "Upload your own .log → real data" (or go to
# http://localhost:8001/app) to upload your .log file there
```

Command line only:

```bash
python main.py run --log mylogs.log --db out.duckdb
python main.py run --log mylogs.log --db out.duckdb --topology topology.json --ground-truth truth.json
```

Multi-core (Advanced tier, for large logs):

```bash
python main.py run --log mylogs.log --db out.duckdb --workers 4
python main.py run --log mylogs.log --db out.duckdb --workers 0  # all cores
```

Workers are processes (not threads - threads share the GIL and
would not speed up parsing). Each worker parses and detects on its
own byte-range chunk, returning only detections. Aggregate rules
(e.g. brute force) are replayed globally in the main process, so a
sequence split across chunks is not missed. Linking, risk scoring
and DuckDB writes stay in the main process, exactly as single-core.

API: `GET /health`, `GET /incidents`, `GET /incidents/{id}/path`,
`GET /incidents/{id}/report`, `GET /incidents/{id}/next`
(`?hindi=1` for the Hindi report), `GET /db/stats` (table counts,
DB size, top techniques), `GET /progress` (live upload progress).

Upload progress, in plain words: while a file uploads, the dashboard
shows what the backend is doing, step by step - (1) receiving the
file, (2) reading line by line and checking each line against the
rules, (3) linking flagged lines into attack paths and scoring risk,
(4) saving incidents - plus lines read, detections so far, speed in
lines/sec, and an estimated time left.

Large incidents stay readable: an incident with more than 50 steps
gets a grouped report (distinct techniques, counts, first/last
times) instead of every step printed one by one, and its path API
response is capped at a summary plus the first/last 200 steps
(`?full=1` for the complete timeline). Logs with no user field
(e.g. Fortinet device logs) show "Unknown - not recorded in the
logs" instead of a blank user, and the graph map has no blank node. The estimate comes from the
file size divided by the average line length sampled from the first
200 lines, so it is labelled as an estimate and updates as speed
changes. Uploads are streamed to disk in 1 MB chunks, never loaded
whole into memory, so a very large file does not blow up RAM on
upload (tested: 213,000 lines / 26 MB in ~65s, progress polling
showed receiving → reading with a live ETA).

Merged from Amogh's `timess` update (code only, UI untouched):
- **O(n²) → O(1) incident lookup** - `cli.py` and `parallel.py` used
  `all_detections.index(d)` for every detection; now a dict built once
  (`det_id_map`) maps object id → detection id.
- **O(n) → O(1) aggregate pruning** - brute-force state is a `deque`,
  old timestamps are popped from the front instead of re-filtering
  the whole list on every event.
- **Batch DB writes** - `store.py` uses `executemany` for incident
  detections and edges instead of one INSERT per row.
- **Windows support** - `cli.py` falls back to a Win32 peak-memory
  reading when `resource` is unavailable; `parallel.py` reuses it.
- **Fortinet KV log parser** - `parser.py` now parses `key=value`
  logs (Fortinet style: `date= time= devname= srcip= msg=` etc.).
- **Synthetic log generator** - `generate_logs.py` + `sample_attack.log`
  (60 benign + 11 attack steps, synthetic only, for testing; the
  dashboard does not load it automatically).
- Two fixes applied on merge: the Fortinet virus branch set an action
  no rule matched, so a virus line was dropped - a `malware_detected`
  rule now matches it; the attack branch overwrote `logdesc`, so it
  now keeps it in the action.

Docker:

```bash
docker compose up --build
# then open http://localhost:8001
```

## How it works

- `frontend/` - dashboard page (upload, incidents, conveyor belt
  with pressable package buttons, timeline, graph, report). No build step.
- `engine/` - backend: streaming parser, Sigma-style YAML rules,
  DuckDB store, NetworkX graph, risk scoring, reports, live tailer.
- `rules/` - detection rules as YAML. Add a rule by editing a
  file here, not code.
- `main.py` - serves the frontend and the API, and runs uploads
  through the real pipeline.

## Everything from before, also in this repo

- `showcase.html` - the devinthehood-style showcase dashboard
  (split cream/black, red seam, chapters, mission/loadout).
  Open it directly in a browser.
- `index.html` + `app.js` + `pass3.js` + `pass4.js` + `styles.css`
  + `adapters.js` - the original browser demo with scenarios,
  plain-English story, what-if blocker, timeline scrubber and
  attack graph. Open `index.html` directly, no server needed.
- `dashboard.html` - single-file browser-only upload dashboard
  (no Python needed, just double-click it).
- `web-app/` - reference source of the hosted full functional app
  (TypeScript port, not standalone runnable; run `main.py` for
  the real thing).
- `WORKFLOW.md` - full workflow and design breakdown.

Hindi reports use the Sarvam API only when `SARVAM_API_KEY` is
set in a private `.env`; without a key they are a clearly labelled
template, never a claimed real translation.

## New dashboard UI (2026-11-01)

- The workspace at `/app` is now a 3-column layout like the reference
  screenshots: Incident Triage Queue (left), attack graph canvas
  (centre, Kill Chain graph, pan + zoom), and Flow
  Log Data / Sarvam Brief / Attack Paths (right).
  The header now says **ASK**, not "ASK Dashboard". The "How ASK
  works - the story, in plain words" section was removed from `/app`.
  No emojis are used in the dashboard UI.
- **Dark / light theme:** the button beside GitHub on both `/` and
  `/app` toggles the theme, saves it in the browser
  (`localStorage: ask_theme`), and the change animates over 0.35s
  (colours only, never layout). Default is light, matching the
  reference screenshots.
- **Graph canvas:** nodes are laid out left-to-right by role
  (Users → Sources → Pivots → Destinations), coloured by worst
  severity, capped at the 60 most-connected nodes by default with a
  "Show all" button, with technique / severity / search filters and
  zoom controls in the centre header. The graph always shows the
  full Kill Chain, with no invented probabilities.
- **Load Sample / Tiny Demo:** `/app` now has Load Sample (runs the
  repo's `sample_attack.log` through the same pipeline) and Tiny
  Demo (5 synthetic rows: 1 benign ingress, 3 attack steps,
  1 benign DNS), alongside Upload and Demo. Both are server-side
  endpoints (`POST /sample`, `POST /tiny`), not browser data.

## Sarvam API key - exact location, and report languages + PDF

1. Copy `.env.example` to a file named exactly `.env` in the repo
   root (the same folder as `main.py` - NOT in `frontend/`).
2. Put only this line in it, with your real key:
   `SARVAM_API_KEY=your-key-here`
   Never commit `.env` - it is already in `.gitignore`.
3. **Restart the server** (Ctrl+C, then `./run.sh` / `run.bat` /
   `python main.py serve …` again). The server reads `.env` once at
   startup; reloading the page alone does not load a new key.
4. In `/app`, pick an incident, then use the Report language
   dropdown in the Sarvam AI Forensic Brief panel: **English, Hindi,
   Tamil, Telugu, Malayalam**. English is generated locally.
   The other four go through Sarvam Translate (`en-IN` → `hi-IN` /
   `ta-IN` / `te-IN` / `ml-IN`) only when the key is set; without a
   key, or if Sarvam fails, the panel shows the English report with
   an explicit warning that it was NOT translated - no fake
   Tamil/Telugu/Malayalam template is ever invented.
5. **Generate PDF** opens the current report in a print view - choose
   "Save as PDF" there. That path uses your system fonts, so Hindi,
   Tamil, Telugu and Malayalam print correctly. API: the same
   translation is available as
   `GET /incidents/{id}/report?lang=hi|ta|te|ml` (English: `?lang=en`).

## Severity, Low tier, and intrinsic priority (2026-11-01)

- `engine/severity.py` is the single place severity is decided.
  `normalize_severity()` accepts any casing and Fortinet level
  synonyms (`critical`/`CRITICAL` -> Critical, `notice`/
  `information` -> Low, etc., including the `.title()` rule), so a
  lowercase "critical" no longer falls through to the Medium weight.
  Weight lookups fall back to Low (3), never Medium (10).
- Missing severity no longer defaults to Medium at the parser,
  detector, or store. A matched detection with no severity
  information is Low, so single probes, blocked notice events, and
  benign scans stay in the Low tier (risk 0-39) instead of being
  pushed to Medium (base 40).
- Intrinsic priority: the final severity is the higher of the log
  line's own severity and the MITRE technique's intrinsic severity
  (Critical: T1003 LSASS/credential dumping, T1048 exfiltration,
  T1485/T1486/T1490 destructive impact; High: T1558 Kerberoasting,
  T1071 C2, T1021 remote services, T1059 PowerShell, T1204
  malicious file, T1505 web shell, T1136 create account, T1053
  scheduled task, T1070 log clearing, T1566 phishing). Recon /
  scanning techniques are deliberately not in that map, so a probe
  stays Low. Exception: if the action was blocked/denied/dropped,
  the attack did not succeed, so intrinsic priority does not upgrade
  it and the log line's severity stands.
- The dashboard queue tiers are now All / Critical / High / Medium /
  Low, matching the backend risk tiers (90-100 / 70-89 / 40-69 /
  0-39). Low is its own tier, not folded into Medium or Elevated.
- Theme toggle is now sun/moon SVG icons (not text, not emojis)
  beside GitHub on `/` and `/app`; the icons cross-fade and rotate
  over 0.5s when the theme changes, in both directions.
