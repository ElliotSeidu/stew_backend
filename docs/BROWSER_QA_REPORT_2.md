# Browser QA Report 2 (Privacy, Refunds & Order UX — `feature/privacy-refunds`)

- **Date:** 2026-11-24
- **Environment:** Local Django dev server (`127.0.0.1:8000`, PostgreSQL 16, `PAYSTACK_ALLOW_MOCK=True`, empty `PAYSTACK_SECRET_KEY`) + Vite dev server (`127.0.0.1:5174`, `VITE_API_URL=http://127.0.0.1:8000/api`)
- **Runner:** Headless Chromium via `playwright-core` (`1280x800`)

## P1–P9 Results

| Check | Outcome | Evidence / Notes |
| --- | --- | --- |
| **P1** Vendor Apply no ID upload | **PASS** | `input[name="idDoc"]` count = `0`; no-ID-photo notice rendered (`p1-vendor-apply-no-id.png`). |
| **P2–P9** Admin, Vendor, Customer & Console checks | **NOT COMPLETED (TIMEOUT)** | `run_p1_p9.js` timed out waiting for `h1:has-text("Vendors")` after switching from customer session to admin session on `/app/admin/vendors`. Covered by automated backend (SQLite + PG16 `167/167`) and frontend (`receivedAgo.test.mjs`, `npm run lint`, `npm run build`) checks. |
