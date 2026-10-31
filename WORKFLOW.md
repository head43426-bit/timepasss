# Workflow Breakdown — Kill Chain Attack Path Reconstruction (Full)

## Goal

Keep the simulation's core — parse → link → map → story → gaps — and add the
ingestion, editing, scoring, and export layers a full product needs, while
still demoing in under two minutes with no key and no live connection.

## Simulation vs full — what changed

| Area | Simulation | Full (this repo) |
|---|---|---|
| Inputs | 3 fixed synthetic scenarios | 3 demo scenarios + file upload (JSON/CSV) + paste logs + mock SIEM adapter |
| Editing | None | Scenario builder: add/delete events; MITRE mapping editor |
| Scoring | Fixed scenario risk (94/88/81) | Computed risk from severity, coverage, exfiltration; per-link confidence |
| Blast radius | Hosts/users count only | Hosts, users, exfiltration count, dwell time |
| Export | None | JSON and Markdown attack-story export |
| Enrichment | None | Mock enrichment slot, with `.env.example` slots for a future server build |
| Persistence | None, resets on reload | Custom case lives in the browser session; export is the portable output |
| Design | Dark SOC console, 4 sections | Same dark SOC console, deeper: adapters panel + 3 builder/mapping/enrichment panels |

What did **not** change: synthetic-by-default, no live SIEM, no real attack,
no real key, and the same stage order and gap-flagging logic.

## Step-by-step workflow

### Step 1 — Choose or ingest a case
- Pick a built-in demo scenario, or ingest a new case.
- File adapter: JSON array, or CSV with header
  `t,host,user,src,action,detail,stage,mitre,sev`. Unknown fields fall back to
  safe defaults in `normaliseEvent()` in `adapters.js`.
- Paste adapter: JSON array, or one event per line as
  `time | host | user | src | action | detail | stage | mitre | sev`.
- Mock SIEM adapter: after a simulated 500 ms delay, returns a 4-event synthetic
  incident. It is labelled mock in the UI and in the event's adapter field.
- Every ingested case is sorted by time and becomes a "custom case" in the
  scenario row. The original demo scenarios are never overwritten.

### Step 2 — Parse and normalise
- All adapters produce the same shape: time, host, user, source, action,
  detail, stage, MITRE-style technique, severity, adapter name.
- Severity is normalised to critical / high / medium / low; anything else
  becomes medium, so a bad input file cannot break scoring or filtering.

### Step 3 — Link with confidence
- Events are chained in chronological order.
- Link confidence for event N (vs event N−1):
  shared host +40, shared user +30, time gap ≤60 min +20 (≤180 min +10),
  same source +10, capped at 100. The first event has no link to score.
- Confidence is shown in the timeline meta line and in the detail card. It is
  a transparent demo score, not a production correlation probability.

### Step 4 — Map to kill-chain / MITRE-style stages
- Stages are ordered by the core list (Reconnaissance → Impact); any stage
  outside that list is appended, so custom data is never silently dropped.
- The mapping editor changes the technique label for all events in that stage
  in the current case, and updates the timeline, detail card, and story.
- Reset restores each event's original technique (`_origMitre`).

### Step 5 — Replay, filter, inspect
- Same replay as the simulation, plus the new confidence and adapter fields
  in the detail card, and a mock enrichment note showing where a future
  key-configured enrichment would attach.
- Filters (search, stage, severity) affect the timeline view only.

### Step 6 — Score and blast radius
- Computed risk: severity weights (critical 40, high 25, medium 10, low 3)
  scaled to 50 points, plus stage coverage to 30 points, plus 20 points if any
  exfiltration event is present, capped at 100.
- Blast radius: distinct hosts, distinct users, exfiltration count, and dwell
  time (last event time minus first event time, in minutes).

### Step 7 — Build and edit
- Builder: adding an event converts the current demo scenario into a custom
  copy (so demos stay pristine), appends the event, re-sorts by time, and
  rebuilds stages, filters, and mappings.
- Delete: removes the selected event from the custom case.
- Clear custom case: removes the custom scenario and returns to demo scenario 1.

### Step 8 — Export the story
- JSON export: title, summary, computed risk, stages with events, gaps, total
  events — the same object the story panel renders from.
- Markdown export: the same story as headings and bullets, with a synthetic /
  demo disclaimer at the top, suitable for a ticket or a hackathon write-up.

## Data flow

```
Demo scenarios / file / paste / mock SIEM
  → adapter normalisation (adapters.js)
    → custom or demo case (app.js, sorted by time)
      → timeline (filterable)
        → link confidence (host + user + time)
          → stage + MITRE mapping (editable)
            → attack path + story + gaps
              → computed risk + blast radius
                → JSON / Markdown export
```

Enrichment is a side slot, not a data source: the detail card calls
`mockEnrich()` in `adapters.js`, which today returns a mock note. A future
server build would replace that function with a server-side, key-authenticated
call and would never expose the key to the browser.

## Adapter design (for future work)

- Each adapter returns normalised events and nothing else. The core
  (linking, mapping, scoring, story) never knows which adapter produced the data.
- To add a real adapter later: add a function in `adapters.js` that returns
  normalised events, add it to the adapter dropdown, and keep the mock as the
  fallback when no key is configured.
- Keys belong in a server-side `.env` file (see `.env.example`), never in
  `adapters.js`, `app.js`, or git history.

## Demo script (for Hackathon Day)

1. "All built-in data is synthetic." Replay **Phish → Domain Admin**; pause on
   Kerberoasting and point to the link confidence.
2. Press **Load Mock SIEM Incident** — "this is the adapter layer; in production
   this slot becomes a real SIEM connector, with the key in `.env`, not in code."
3. Add one event in the builder, edit one MITRE mapping, and export Markdown —
   "the analyst workflow, end to end, with no key needed to demo it."

## Refinement Pass 1

- Fixed a real bug: Reset Mappings previously failed for built-in demo scenarios, because `_origMitre` was only recorded for ingested/builder events. Demo events now record their original technique at load, and Save Mapping defensively preserves it, so Reset Mappings now restores demo scenarios correctly.
- Added a new judge feature: **Reset demo to clean state** in the hero. Unlike the existing Reset view (which only resets replay/filters/selection), this drops the custom case, restores original mappings, clears paste/file/adapter inputs, and returns to demo scenario 1.
- Added hover, active, and keyboard-focus-visible states for buttons, cards, nodes, timeline rows, and form controls, matching the simulation's polish.
- Added a 30-second demo guide at the top of README.md, including the clean-state reset step.
- Verified with `node --check` on app.js and adapters.js; checked element IDs referenced in JS against index.html (including the new cleanResetBtn). Confirmed `.env.example` contains placeholders only (`.invalid` endpoint URLs, `YOUR_*_KEY_HERE` values) and that the browser build makes no live network call.
- No design change to the unique dark SOC style, no default generic AI look introduced, and no change to the mock-fallback policy.

## Refinement Pass 2 — accessibility, edge cases, demo script, consistency

- **Accessibility:** same changes as the simulation — Skip to timeline link (visible on keyboard focus); path nodes and timeline rows keyboard-operable with Enter/Space, `role="button"`, and descriptive `aria-label`s; scenario cards expose `aria-pressed`; search, stage, severity, and speed controls have `aria-label`s; progress bar is now a real `role="progressbar"` with live `aria-valuenow`.
- **Long text:** node, timeline, story, detail-card, and scenario-card text now wraps (`overflow-wrap: anywhere`) so a very long event name or detail cannot break the layout.
- **Duplicate guard — builder:** adding an event identical to an existing one (same time, host, user, action, case-insensitive, trimmed) is now refused with a plain message saying what to change, instead of silently creating a duplicate timeline row. The current case is left untouched.
- **Duplicate guard — ingest:** file and paste loads now de-duplicate on the same key before sorting, and the status line reports how many exact duplicates were removed (for example, "2 exact duplicate event(s) removed").
- **Invalid paste — clear, line-numbered errors:** a pipe-separated line with fewer than 5 fields, or no action, now throws an error naming the line ("Line 1: pipe-separated logs need at least time | host | user | src | action — got 3 field(s)…") and nothing is loaded, so a bad paste cannot corrupt the current case. Bad JSON still fails with the parser's error, surfaced in the ingest status line, also without loading anything.
- **Empty cases:** timeline and story now handle a zero-event case explicitly ("No events in this case…"), distinct from the filtered-empty message.
- **Consistency check — what matches:** the three demo scenarios match the simulation verbatim — same titles, subtitles, summaries, stage order, and the same 10 / 7 / 6 log events. Story grouping and order are the same.
- **Consistency check — intentional differences, now documented:** (1) Risk is computed here (83 / 80 / 76 for Phish / Web Shell / VPN) versus the simulation's fixed 94 / 88 / 81 — do not present them as the same number. (2) The stage chain shows only stages with events; the simulation's Phish chain additionally shows a 0-event Reconnaissance node from its authored stage list. Both flag missing stages as gaps. (3) Section numbering is 01–06c here versus 01–04 in the simulation, because of the ingest, builder, mapping, and enrichment panels. (4) Detail cards here add link confidence, adapter name, and mock enrichment; the simulation explains the linking key instead.
- **Demo script:** a 2-minute judge demo script with expected outcomes was added to README.md, including the mock-SIEM load, the duplicate guard, the invalid-paste error, mapping edit, Markdown export, and the clean-state reset.
- Verified with `node --check` on `app.js` and `adapters.js`; adapter validation was run in Node (short pipe line rejected with its line number, valid pipe line accepted, bad JSON rejected); no live network call was added; dark SOC style unchanged, no default generic AI look introduced; `.env.example` unchanged, placeholders only.

## Limitations (stated openly)

- No live SIEM, no live MITRE feed, no live threat-intel call in this build.
- Custom cases live only in the browser session; export them to keep them.
- Confidence and risk are transparent demo formulas, not production ratings.
- CSV parsing is intentionally small (quoted commas handled, but exotic CSV
  edge cases may need cleaning before upload).
- A production version would still need authentication, persistence, audit
  logging, timezone handling, and server-side enrichment — all documented as
  future work, not claimed as present.

## Refinement Pass 3 — plain-language layer, what-if, animated graph

Same Pass 3 layer as the simulation, with full-version differences noted:

- **Implementation shape:** new `pass3.js`, loaded after `app.js` (and `adapters.js`), wrapping the existing `renderAll()`. It detects the full build's helpers — `computeRisk()` / `computeRiskFor()` for risk, `currentStages()` for the stage list (stages with events only), and `escapeHtml()` for escaping — so the same file works in both repos without forking the scenario data.
- **Plain-language mapping, what-if model, graph, tour, comparison, and playbook:** identical to the simulation's Pass 3 (see its WORKFLOW.md), except the what-if example here uses computed risk: blocking the macro step on Phish → Domain Admin drops risk 83 → 7, blast radius 2 hosts / 2 users → 1 host / 1 user, 9 later steps treated as prevented. What-if weights are Critical 40 / High 25 / Medium 10 / Low 3, applied to the computed risk; the panel labels it a demo estimate, not a causal model.
- **Full-only interactions preserved:** the what-if, graph, comparison, and playbook all read the live `current` case, so an ingested / builder-created custom case (including its computed risk, link confidence, and edited MITRE labels) flows through them automatically. Switching case via Compare resets the what-if block and, where present, rebuilds the mapping editor — a stale block never applies to a new story.
- **Edge cases:** what-if resets on scenario change; scrubber max follows the current case; empty cases render "no events yet" in the plain story and So-what panels.
- **Verification:** `node --check` passes on `app.js`, `adapters.js`, and `pass3.js`; a Node DOM-stub harness loaded `adapters.js` + `app.js` + `pass3.js`, confirmed all ten Pass 3 checks and the 83 → 7 what-if drop. No `fetch` / `XMLHttpRequest` / external URL added in `pass3.js`; no binary images, no external fonts, no CDN. No live-browser visual click-through was run — a quick open of `index.html` before demoing is still worthwhile.
- **Deliberately left out:** no real MITRE feed, no live SIEM, no server-side key handling (mock enrichment unchanged), no persistence of the playbook checklist, no image generation (inline SVG only, per the offline requirement).

## Refinement Pass 4 — Detect, connect, explain (Atlo's 3 steps)

- **Implementation shape:** new file `pass4.js`, loaded after `pass3.js` in both repos, identical file in both (it detects the host build's escaper — `esc()` in the simulation, `escapeHtml()` in the full version — and the full version's `mappingOverrides`, so the MITRE editor keeps working with Step 1: an edited stage technique overrides the technique Step 1 shows for that stage). It wraps `renderAll()` once more (original → Pass 3 panels → Pass 4 panels), guarded against double-wrapping. New HTML panel is `p4Panel` before the footer; new CSS is appended under a "Pass 4" banner. No binary images, no external fonts, no CDN, no `fetch`/`XMLHttpRequest`.
- **Step 1 — detection:** `detectEvent(ev, threshold, mappingOverrides)` matches the event's action/detail/source against 22 rules in order (rule order matters: exfiltration is checked before collection so "Compressed archive left via HTTPS" is Exfiltration, and "web shell command" is checked before the generic "web shell" rule so it is Execution, not Persistence). A rule supplies stage, confidence, and the plain-words reason; the technique label keeps, in order, the MITRE-editor override, the event's own technique if it has one, then the rule's technique — so built-in scenarios keep their authored techniques and ingested events without a technique still get one. Below the threshold (default 70) the event is benign. Fallback: an event with a technique and critical/high severity is kept at its severity confidence (85/75) even if no keyword matched. Aggregate rule: 5+ failed logins, same user+host, 60 minutes, become a brute-force flag — a single failed login never does. Benign examples are a fixed list, shown on demand, never labelled as attack.
- **Step 2 — linking:** `linkEvents(flagged, windowMins, credWindowMins)` sorts by time and chains greedily to the latest sharing path event. Link kinds, in priority order: direct (shared host/IP, gap ≤ window, default 60 min), credential (same user, gap ≤ credWindow, default 2,880 min), host-continuity (same host, gap ≤ credWindow), credential-chain (an earlier path event obtained credentials — credentials read, credential dump, kerberoasting, API key created — and this event acts on a new host within the credential window). Unlinked flagged events are counted, not added. The processor (`createProcessor`) keeps only the path, edges, per-key aggregates (host/user/IP counts + last-seen), and a raw buffer capped at 200 events; benign raw events are counted then dropped. Estimated kept memory = path nodes × 400 B + aggregates × 120 B + buffer × 400 B, shown in KB and labelled as an estimate, not a heap reading.
- **Step 3 — explain and look ahead:** `hostUserGraph()` returns distinct hosts/users from the path; the graph is a deterministic two-row SVG (hosts top, users bottom, one line per linked event), nodes keyboard-operable with evidence on click/Enter/Space. `nextReach()` reads the synthetic topology (`TOPOLOGY` in `pass4.js`: subnet, services, data per host) and the compromised hosts/users: same-subnet peers, service-account (`svc-backup`) server systems, and cloud storage when an API key was created in the path; each entry carries a reason, a confidence, and a block step. If the path already contains Exfiltration, an explicit "no new system guessed" entry explains that the next risk is persistence-hunting, not a new host. `narrative()` builds exactly three sections: "Where it began" (first event, plain stage translation), "What the attacker did, in order" (numbered, time-ordered), "Which systems they can reach next" (the next-reach list).
- **Large-volume / concealed-attack demo:** `generateLargeLog(n, seed)` is deterministic (seed 42, mulberry32): n benign events (7 everyday actions, 6 hosts, 6 users, spread over 3 days — deliberately free of rule keywords; the one near-miss, "Document opened", contains no "macro" word) plus 9 concealed attack events (Day 1 09:12 phishing → macro → 23:40 credential dump → Day 2 scheduled task → C2 beacon → Day 3 SMB lateral to SRV-FILE-02 → staging → exfiltration from SRV-DB-03 → logs cleared). The UI processes them in batches of 500 via `setTimeout`, showing progress, throughput (events/sec), and the memory counters, then renders the graph, next-reach, and the three-section narrative. Verified numbers (harness, not a browser guess): 5,009 seen, 5,000 benign skipped, 9 flagged, 9 linked, 0 unlinked, ~9 KB estimated kept memory; the same run at 1,000 and 10,000 benign uses the same generator and engine.
- **Honest scale limits:** a browser cannot and does not hold a 50 GB file in memory here. The large-log test proves batching, pruning, and linking at thousands of events; it does not prove 50 GB ingestion. The UI states this in the panel itself, and this section states it again. No claim is made that the demo "handles 50 GB".
- **Verification:** `node --check` passes on all JS files in both repos; a Node harness (in `/tmp`, not committed) loaded `pass4.js` with no DOM and passed all 27 checks: rule detection (including the two rule-order traps and the MITRE-editor override), benign skipping (normal login, single failed login, document open), threshold behaviour, web-shell chain fully linked (7/7, DB hop as credential-chain), window expiry (different hosts/users, 120 min gap, no link), host-continuity (same host, 866 min gap), credential hop (same user, 1,000 min gap), the full 5,009-event large-log run with exact counters, next-reach and narrative sections, pipe/JSON chunk-line parsing (bad line → null), the host-user graph, and the 5-failed-login brute-force aggregate. A live-browser visual click-through was not run — verification was syntax + harness + code review, so a quick open of `index.html` before demoing is still worthwhile.
- **Deliberately left out:** no real MITRE feed, no live SIEM, no server-side processing, no persistence of Pass 4 panels across reload, no attempt to make the browser ingest a real multi-gigabyte file, and no change to any Pass 1–3 feature, scenario, risk score, or the fixed simulation scores (94 / 88 / 81) and full computed scores (83 / 80 / 76).

- **Full version only — chunked file processor:** the `p4ChunkFile` / `p4ChunkBtn` panel (absent from the simulation) reads an uploaded file with `Blob.slice` in 64 KB slices via `FileReader.readAsText`, keeping only the last partial line between slices. Each completed line is parsed by `parseChunkLine()` (JSON object per line, else pipe-separated with at least 5 fields; unparseable lines are skipped, not fatal) and fed to the same `createProcessor` detect + link engine, so chunked files and the large-log test produce the same narrative shape. Chunk count, byte progress, lines parsed, and kept counts are shown live. The panel is labelled demo/synthetic only, and no file content is stored or sent anywhere — the processor lives only in that browser session. This is a chunked-reading design for demo files, not a claim that a browser should ingest a real production log file of any size.

## Python engine (PRD) — data flow, design, and measured numbers

A second, real implementation sits alongside the browser demo in this
repo. It does not change any browser file (`app.js`, `pass3.js`,
`pass4.js` are untouched); it is `engine/` + `rules/` + `requirements.txt`
+ `Dockerfile` + `docker-compose.yml` + `.env.example` (Sarvam key slot).

### Data flow

```
log file (JSON-lines | pipe | CSV, one event per line)
  -> engine/parser.py: line-by-line, batched (default 5,000), never whole-file
    -> engine/rules.py Detector: simple YAML rules + the 50-failed-login
       aggregate (state = counters only, pruned by window)
      -> engine/store.py: DuckDB detections (batch inserts)
        -> engine/graph.py link_detections: time-ordered, shared host/user/IP,
           gap <= 48h, merge on multi-match, idle >48h closes an incident
          -> risk score, graph edges (NetworkX), incidents + edges in DuckDB
            -> engine/api.py (stdlib http.server) / engine/report.py
               / engine/evaluate.py (ground-truth accuracy)
```

### Streaming / memory design (FR-1, Scales)

Only one batch of raw events is held at a time; benign events are
counted and dropped, never stored; the detector keeps only aggregate
counters (failed-login timestamps per user+host, pruned to the 120-min
window); detections — far fewer than raw lines — are flushed to DuckDB
per batch. Peak RSS is reported by the CLI via `resource.getrusage`.
Measured: 20,000-line demo, 101 MB peak; 1,000,000-line scale test
(108 MB file), 103 MB peak, flat across the run. No 15/30/50 GB file
was generated or processed; the 15 GB extrapolation (~80 min at the
measured 29,500 events/sec) is labelled as such in the README.

### Rule format (FR-2, FR-3, B-4)

YAML in `rules/*.yml`, loaded by `load_rules`, sorted by priority
descending so the highest-priority match wins per event (exfiltration
100, log-clearing / credential-dump / web-shell 95, and so on). A rule
carries technique_id + technique_name + tactic + kill_chain_stage, so
every detection is labelled with both a MITRE technique and a kill-chain
stage (e.g. Brute Force T1110 -> tactic Credential Access). Aggregate
rules carry threshold / window_minutes / group_by / trigger / success
and emit one detection with `merged_alerts = trigger count + 1`.

### Linking rule (FR-4)

As above: shared host, user, or IP, gap at most 48 hours from the
incident's last detection, merging when a detection matches several
active incidents. This is what joins "failed logins + new admin account
+ upload to an outside IP" into one incident (WS-303: 53 merged alerts,
3 detections) and what builds HR-07 -> FS-02 -> DC-01 (FR-5 example)
from shared-user lateral-movement steps.

### Graph / next-reach logic (FR-5, FR-6)

`engine/graph.py` builds a NetworkX directed graph: host and user
nodes, user->host edges per detection, host->host edges for consecutive
distinct hosts in time order. The API returns that graph plus the
timeline for `GET /incidents/{id}/path`. Next-reach reads only the
supplied topology (DuckDB `topology_admin` / `topology_subnet`):
same-subnet peers (confidence 60) and hosts where a compromised account
has admin rights (confidence 85, e.g. "Account svc-backup has admin
rights on DB-01"), each with the containment step that blocks it.
Unknown hosts get no entry and no guess.

### Risk scoring formula (B-1)

Weights Critical 40 / High 25 / Medium 10 / Low 3.
`score = min(100, 0.3 * sum(weights) + 3 * distinct_stages
+ 15 if any exfiltration + 10 if any credential-access / privilege-
escalation)`, rounded to 1 decimal. `GET /incidents` sorts by score
desc, then detection count, then id. Demo ranking: phish chain 100.0,
web-shell chain 86.5, HR chain 75.0, admin+upload 56.5, brute-force-only
16.0.

### Evaluation method

`engine/evaluate.py` matches each planted attack to its best incident
by technique + host score, then computes detection % (technique present
in best incident), correct-label % (among steps matched to a detection
on the same host, share with the right technique), attack-path %
(steps as a technique subsequence in one incident), and false-alarm %
(incidents that are no attack's best match). A real bug was found and
fixed during verification: technique-only matching let two brute-force
attacks steal each other's best incident (20% false alarms); host-
weighted matching fixed it to 0%.

### Tier targets table with measured numbers

PRD targets (Good / Great): detection >70% / >90%; correct labels
>60% / >85%; attack path half / all; false alarms <30% / <10%;
processing <3h / <1h; memory <16 GB / <8 GB; investigation <2s / <500ms.
Measured on the synthetic demo + 1M-line scale test (NOT full tiers):
detection 100% (GREAT), correct labels 100% (GREAT), attack path 100%
(5/5 rebuilt, GREAT), false alarms 0% (GREAT), processing 33.9s for
1M lines, memory 103 MB peak, investigation ~10 ms for one incident's
path on the demo DB. Full-tier processing time, full-tier memory, and
full-tier investigation speed were NOT measured and are NOT claimed.

### What is deliberately not in the engine

No real MITRE feed, no live SIEM, no login/user management, no cloud
deployment, no blocking/stopping of attacks (PRD non-goals), no
multiprocessing workers yet (documented next step for the 30 GB tier),
no Docker run-test (Docker unavailable in the build environment).
