# STEW Staging Deployment Log

No secrets, passwords, API keys, or tokens are ever recorded in this log.

## Phase 0 — Preconditions (2026-11-24)
- **Base tag:** `rc4` (on `feature/privacy-refunds` in both `stew_backend` and `stew`)
- **Branch created:** `chore/render-staging` from `rc4` in both repos
- **Backend SQLite:** `167` tests passed (`4` PG16-only concurrency tests skipped)
- **Backend PostgreSQL 16:** `167` tests passed (`0` skipped)
- **Frontend:** `npm run lint` (`0` errors), `npm run build` passed (`dist/` + `dist/sw.js`)
