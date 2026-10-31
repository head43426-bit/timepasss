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

Hindi reports use the Sarvam API only when `SARVAM_API_KEY` is
set in a private `.env`; without a key they are a clearly labelled
template, never a claimed real translation.
