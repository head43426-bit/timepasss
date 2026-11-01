# ASK — Analyse Secure Kill

> **Kill Chain Attack Path Reconstruction.**
> Turn a security log into one attack story: where it began, what the
> attacker did, which hosts they can reach next, and what to do about it.

| | |
| --- | --- |
| **Stack** | Python + DuckDB + NetworkX |
| **Detection** | Deterministic rules — no machine learning, no LLM in the detection path |
| **Data** | Logs stay on your machine |

> **Use only synthetic or authorised logs. Never real production logs or credentials.**

---

## Contents

- [Run it](#run-it)
- [Use it](#use-it)
- [How much works today](#how-much-works-today)
- [Docker](#docker)
- [Formats and rules](#formats-and-rules)
- [Command line](#command-line)
- [Reports in other languages](#reports-in-other-languages)
- [Main API](#main-api)
- [Layout](#layout)
- [Limits, stated plainly](#limits-stated-plainly)

---

## Run it

```bash
./run.sh        # Windows: run.bat
```

That is the whole setup. It creates its own virtual environment on
first run and installs only `duckdb`, `networkx`, and `pyyaml`.
Then open the link it prints, usually http://localhost:8001.

Manual run, if you prefer:

```bash
pip install -r requirements.txt
python main.py serve --db out.duckdb --port 8001
```

| Page | What it is |
| --- | --- |
| `/` | Landing page |
| `/app` | Incident workspace |

---

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

**For each incident you get:**

| Output | Detail |
| --- | --- |
| Risk tier | Critical 90–100, High 70–89, Medium 40–69, Low 0–39 |
| Host graph | Source, pivot, and destination hosts |
| Attack path | The chain through the incident, with all boxes |
| Report | Plain-English, minimal on the page, detailed for Copy / PDF |
| Protections | Per-technique actions to apply |
| Look-ahead | Next hosts already contacted, plus an observed blast radius |

Large incidents are grouped instead of printing every step.

---

## How much works today

This is the honest state, not a percentage. Everything below was
run on synthetic logs, not on a real production log.

### ✅ Works, and verified locally

| Area | What works |
| --- | --- |
| **Detect and label** | 29 Sigma-style YAML rules, 27 techniques. Every detection carries a MITRE technique, tactic, and kill-chain stage, plus severity, confidence, rule id, and reason. |
| **Connect** | Detections are linked into incidents across host, user, IP, and time, with a streaming linker that keeps only active incidents in RAM. |
| **Graph and risk** | A NetworkX host graph (source, pivot, destination), risk tiers with a one-tier downgrade for single-stage incidents, and an observed blast radius. |
| **Look ahead** | Frontier hosts the attacker already contacted but has not yet used as a stepping stone, with a priority in brackets (90 Critical, 70 High, 40 Medium, 20 Low). |
| **Reports and protections** | A minimal report on the page, a detailed report for Copy / PDF, and per-technique protections to apply. ASK itself cannot block anything (see Limits). |
| **Scale, synthetic only** | Sample 71 events / 11 detections / 1 incident; Demo about 100 MB; Load Sample about 250 MB with planted ground truth, which is the only run that produces accuracy stats; a 497,000-line file ran as 77,000 detections / 1 incident in about 45 seconds with parallel workers. Files over about 50,000 lines or 20 MB use parallel workers automatically in the server. |
| **Formats** | Fortinet UTM key-value is the priority format and always gets a fixed rule pack. Other formats load all rules and may struggle — that is accepted, Fortinet is the priority. |

### ⚠️ Partial, or not tested end to end

| Area | Status |
| --- | --- |
| **Live mode** | `--watch` tailing exists in code but has not been tested end to end. |
| **Docker** | A complete compose file exists (below), but it has not been built or run in this environment — Docker is not installed here. |
| **Sarvam translation** | With a real key it has not been tested here; without a key it is a clearly labelled mock, never a claimed translation. |
| **Windows fixes** | Windows-specific fixes (for example, the 0 MB memory fix) were verified on Linux only, not on a real Windows machine. |

---

## Docker

Build and run from this repo, no Hub image needed:

```bash
docker compose up --build
```

Then open http://localhost:8001 and http://localhost:8001/app.
The database persists in a named volume; `docker compose down -v`
clears it.

A Docker Hub image is also published, by Amogh, here:

[amoghvd/ask on Docker Hub](https://hub.docker.com/r/amoghvd/ask)

That image is not built or verified by this repo's compose file —
check its Hub page for its tags and run instructions before using
it instead of building from source.

### Docker Hub deploy

https://hub.docker.com/r/amoghvd/ask

---

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

---

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

---

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

---

## Main API

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Server and database status |
| `GET /incidents` | Incident list |
| `GET /incidents/{id}/path` | Timeline + graph for one incident |
| `GET /incidents/{id}/report` | Minimal + detailed report |
| `GET /incidents/{id}/next` | Look-ahead, frontier hosts, blast radius |
| `GET /db/stats` | Database counts |
| `GET /progress` | Upload / run progress |
| `GET /mitre` | Techniques ASK detects |
| `GET /mitre/{id}` | Explanation for one technique |
| `POST /upload` | Upload a log file |
| `POST /demo` | Generate and run about 100 MB of synthetic log |
| `POST /sample` | Generate and append about 250 MB, with ground truth |
| `POST /clear` | Delete all data in the current database |

---

## Layout

| Path | What it is |
| --- | --- |
| `main.py` | Server, dashboard routes, upload pipeline |
| `frontend/` | `/app` dashboard, no build step |
| `engine/` | Parser, rules, store, graph, risk, reports, live tail |
| `rules/` | Detection rules as YAML |
| `data/` | MITRE technique index |
| `sample_attack.log` | Synthetic sample, 71 lines |
| `generate_logs.py` | Synthetic log generator |
| `showcase.html` | Landing page at `/` |
| `docker-compose.yml` | Whole-app compose file (service `ask`, port 8001) |
| `Dockerfile` | Image build (engine, rules, frontend, data, assets) |
| `.dockerignore` | Keeps local databases and `web-app/` out of the image |

---

## Limits, stated plainly

- **ASK reads logs.** It has no agent on hosts and no firewall control,
  so it cannot actively block anything. "Protect" is advice to
  apply, not an action ASK takes.
- **No real 15 GB, 30 GB, or 50 GB file has been run end to end.**
  Speed and memory numbers come from synthetic tests, not from a
  proven 50 GB run.
- **A log line can only be labelled with what it actually says.**
  Sub-techniques that the line does not distinguish are not claimed.
