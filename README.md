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
# open http://localhost:8001 and upload your .log file there
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
(`?hindi=1` for the Hindi report).

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
