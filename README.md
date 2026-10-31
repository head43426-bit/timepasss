# Kill Chain Attack Path Reconstruction

Turn your security logs into one attack story: where it began,
what the attacker did, and what they can reach next.

**No demo data in this project.** You bring your own `.log` file.
Use only synthetic or authorised logs — never real production
logs or credentials.

## Run it

```bash
pip install -r requirements.txt
python main.py serve --db out.duckdb --port 8001
# open http://localhost:8001 — the showcase is the main page
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

Workers are processes (not threads — threads share the GIL and
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
shows what the backend is doing, step by step — (1) receiving the
file, (2) reading line by line and checking each line against the
rules, (3) linking flagged lines into attack paths and scoring risk,
(4) saving incidents — plus lines read, detections so far, speed in
lines/sec, and an estimated time left.

Large incidents stay readable: an incident with more than 50 steps
gets a grouped report (distinct techniques, counts, first/last
times) instead of every step printed one by one, and its path API
response is capped at a summary plus the first/last 200 steps
(`?full=1` for the complete timeline). Logs with no user field
(e.g. Fortinet device logs) show "Unknown — not recorded in the
logs" instead of a blank user, and the graph map has no blank node. The estimate comes from the
file size divided by the average line length sampled from the first
200 lines, so it is labelled as an estimate and updates as speed
changes. Uploads are streamed to disk in 1 MB chunks, never loaded
whole into memory, so a very large file does not blow up RAM on
upload (tested: 213,000 lines / 26 MB in ~65s, progress polling
showed receiving → reading with a live ETA).

Merged from Amogh's `timess` update (code only, UI untouched):
- **O(n²) → O(1) incident lookup** — `cli.py` and `parallel.py` used
  `all_detections.index(d)` for every detection; now a dict built once
  (`det_id_map`) maps object id → detection id.
- **O(n) → O(1) aggregate pruning** — brute-force state is a `deque`,
  old timestamps are popped from the front instead of re-filtering
  the whole list on every event.
- **Batch DB writes** — `store.py` uses `executemany` for incident
  detections and edges instead of one INSERT per row.
- **Windows support** — `cli.py` falls back to a Win32 peak-memory
  reading when `resource` is unavailable; `parallel.py` reuses it.
- **Fortinet KV log parser** — `parser.py` now parses `key=value`
  logs (Fortinet style: `date= time= devname= srcip= msg=` etc.).
- **Synthetic log generator** — `generate_logs.py` + `sample_attack.log`
  (60 benign + 11 attack steps, synthetic only, for testing; the
  dashboard does not load it automatically).
- Two fixes applied on merge: the Fortinet virus branch set an action
  no rule matched, so a virus line was dropped — a `malware_detected`
  rule now matches it; the attack branch overwrote `logdesc`, so it
  now keeps it in the action.

Docker:

```bash
docker compose up --build
# then open http://localhost:8001
```

## How it works

- `frontend/` — dashboard page (upload, incidents, conveyor belt
  with pressable package buttons, timeline, graph, report). No build step.
- `engine/` — backend: streaming parser, Sigma-style YAML rules,
  DuckDB store, NetworkX graph, risk scoring, reports, live tailer.
- `rules/` — detection rules as YAML. Add a rule by editing a
  file here, not code.
- `main.py` — serves the frontend and the API, and runs uploads
  through the real pipeline.

## Everything from before, also in this repo

- `showcase.html` — the devinthehood-style showcase dashboard
  (split cream/black, red seam, chapters, mission/loadout).
  Open it directly in a browser.
- `index.html` + `app.js` + `pass3.js` + `pass4.js` + `styles.css`
  + `adapters.js` — the original browser demo with scenarios,
  plain-English story, what-if blocker, timeline scrubber and
  attack graph. Open `index.html` directly, no server needed.
- `dashboard.html` — single-file browser-only upload dashboard
  (no Python needed, just double-click it).
- `web-app/` — reference source of the hosted full functional app
  (TypeScript port, not standalone runnable; run `main.py` for
  the real thing).
- `WORKFLOW.md` — full workflow and design breakdown.

Hindi reports use the Sarvam API only when `SARVAM_API_KEY` is
set in a private `.env`; without a key they are a clearly labelled
template, never a claimed real translation.
