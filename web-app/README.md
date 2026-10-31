# Web app - reference copy only

This `web-app/` folder is a cleaned reference copy of the hosted
"Kill Chain Full Functional" app (React client + TypeScript server
actions + Drizzle SQL), pushed for reference only.

**Read this before judging it as the runnable tool:**

- This hosted app **ports** the Python engine's detection, linking,
  and scoring logic into TypeScript server actions. It does **not**
  itself run Python, DuckDB, or NetworkX.
- The **standalone runnable engine** is in this repo's `engine/`
  folder (Python + DuckDB + NetworkX), with `requirements.txt`,
  `Dockerfile`, and `docker-compose.yml`. Judges should run that
  engine - not this folder - to reproduce the DuckDB/NetworkX
  results.
- This folder is **not standalone runnable** as-is: it was built
  for the Muse hosted app runtime. It needs that runtime's server
  actions and database layer, which are not included here.
- The browser demo in this repo (`index.html`, `app.js`,
  `pass3.js`, `pass4.js`) is a separate, fully offline demo.

**What was left out on purpose:**
`node_modules/`, built `dist/` output, `app.db` and its
write-ahead files, audit screenshots, and builder-internal files.
No secrets or keys are included.

**Contents:**
- `client/` - React front end (`src/App.tsx`, `src/api.ts`,
  `src/theme.css`, `src/main.tsx`, `index.html`)
- `server/src/` - server actions (`actions.ts`) and database
  schema (`schema.ts`)
- `drizzle/` - database migrations (`0001_initial.sql`,
  `0002_kill_chain_tables.sql`)
- `package.json`, `tsconfig.base.json`, `bunfig.toml` - app
  packaging and build configuration, as used in the hosted build
