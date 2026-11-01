# ASK - Analyse Secure Kill

Kill Chain Attack Path Reconstruction.

Turn a security log into one attack story: where it began, what the
attacker did, which hosts they can reach next, and what to do about
it. Python, DuckDB, and NetworkX. No machine learning, no LLM in the
detection path.

Use only synthetic or authorised logs. Never real production logs
or credentials. Logs stay on your machine.

## Run it

```bash
./run.sh        # Windows: run.bat
```

That is the whole setup. It creates its own virtual environment on
first run and installs only duckdb, networkx, and pyyaml. Then open
the link it prints, usually http://localhost:8001.

Manual run, if you prefer:

```bash
pip install -r requirements.txt
python main.py serve --db out.duckdb --port 8001
```

`/` is the landing page. `/app` is the incident workspace.

## Use it

- **Upload your own log** at `/app`. Uploads stream to disk, so a
  large file does not blow up RAM.
- **Demo** generates about 100 MB of synthetic log on the server
  and runs it through the same pipeline. No real logs, no download.
- **Load Sample** generates about 250 MB of synthetic log (the
  same 11-step chain as `sample_attack.log`) and appends it to the
  current database. It is the only run with planted ground truth,
  so accuracy stats (detection, labels, path, false alarms) only
  appear after Load Sample.

What you get for each incident: a risk tier (Critical 90-100,
High 70-89, Medium 40-69, Low 0-39), a host graph, an attack path,
a plain-English report, protections to apply, and a look-ahead
(next hosts already contacted, and an observed blast radius).
Large incidents are grouped instead of printing every step.

## Formats and rules

ASK reads the first 200 lines and sniffs the format: pipe, JSON,
CSV, syslog, Fortinet key-value, and plain text. It maps common
field names across formats, including nested JSON and Apple log
fields.

Fortinet UTM key-value logs are the priority format and always get
a fixed rule pack. Every other format loads all rules.

Rules are Sigma-style YAML in `rules/`. Add or edit a rule there,
no code change needed. Detections carry a MITRE technique and a
kill-chain stage. `GET /mitre` lists the techniques ASK detects,
`GET /mitre/<id>` explains one.

## Command line

```bash
python main.py run --log mylogs.log --db out.duckdb
python main.py run --log mylogs.log --db out.duckdb --workers 4
python main.py serve --db out.duckdb --port 8001 --watch mylogs.log
```

`--workers 0` means all cores. Files over about 50,000 lines or
20 MB run on parallel workers automatically in the server;
`--topology` and `--ground-truth` are optional inputs for
look-ahead and evaluation.

## Reports in other languages

Reports are English by default. Hindi, Tamil, Telugu, and Malayalam
go through Sarvam Translate, only when you set a key yourself:

```bash
# .env in the repo root (same folder as main.py, gitignored, never committed)
SARVAM_API_KEY=your-key-here
```

Then restart the server. A page reload alone does not load a new
key. Without a key, or if Sarvam fails, the panel shows the English
report with an explicit warning that it was not translated.

## Main API

```
GET /health
GET /incidents
GET /incidents/{id}/path
GET /incidents/{id}/report
GET /incidents/{id}/next
GET /db/stats
GET /progress
GET /mitre
GET /mitre/{id}
POST /upload
POST /demo
POST /sample
POST /clear
```

## Layout

```
main.py       server, dashboard routes, upload pipeline
frontend/     /app dashboard, no build step
engine/       parser, rules, store, graph, risk, reports, live tail
rules/        detection rules as YAML
data/         MITRE technique index
sample_attack.log   synthetic sample, 71 lines
generate_logs.py    synthetic log generator
showcase.html       landing page at /
```

## Limits, stated plainly

- ASK reads logs. It has no agent on hosts and no firewall control,
  so it cannot actively block anything. "Protect" is advice to
  apply, not an action ASK takes.
- No real 15 GB, 30 GB, or 50 GB file has been run end to end.
  Speed and memory numbers come from synthetic tests, not from a
  proven 50 GB run.
- A log line can only be labelled with what it actually says.
  Sub-techniques that the line does not distinguish are not claimed.
