# STEW Staging Security & Release Verification Report

**Status:** Interim Report (Part A complete; Part B unauthenticated black-box checks complete; Part B authenticated + Part C awaiting human checkpoint)  
**Verdict:** **`NOT YET`** *(Blocked on Vercel & Render serving the latest `staging` commits, `TRUSTED_PROXY_COUNT` calibration, and authenticated/E2E verification)*

---

## 1. Environment & Versions
- **Frontend URL:** `https://stewfrontend.vercel.app`
- **API URL:** `https://stew-backend.onrender.com`
- **Backend Repo (`stew_backend`) Branch:** `staging` (local `chore/staging-hardening` at `b863ae1` ready to fast-forward once SQLite & PG16 suites complete)
- **Frontend Repo (`stew`) Branch:** `staging` (`dc1dadd`)
- **Tooling:** Python `3.13.17`, Node `v26.13.1`, `gitleaks` (WinGet)

---

## 2. Verification Results Table (B1–B9, C1–C9)

| ID | Check | Result | Evidence / Notes |
|---|---|---|---|
| **B1** | TLS & HTTP→HTTPS redirects | **PASS** | `docs/staging-qa/b1-b2-tls-headers.txt` — API HTTP→HTTPS `301`, Web HTTP→HTTPS `308`, valid Google Trust Services certs, API HSTS `max-age=31536000; includeSubDomains; preload`, no `http://` mixed content in HTML. |
| **B2** | API & Frontend headers | **PARTIAL (API PASS / Web FAIL)** | `docs/staging-qa/b1-b2-tls-headers.txt` — API returns CSP, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, `DENY`, `Cache-Control: no-store, private` on `/api/orders/policy/`. **Web (`stewfrontend.vercel.app`) is missing `X-Frame-Options`, `X-Robots-Tag`, `Content-Security-Policy-Report-Only`, `Permissions-Policy`, and `immutable` asset caching** because Vercel is still serving an old `main` build (`Last-Modified: Thu, 26 Nov 2026`). |
| **B3** | CORS origin enforcement | **PASS** | `docs/staging-qa/b3-cors.txt` — `https://stewfrontend.vercel.app` receives exact `ACAO` + `ACAC: true`; `https://evil.example`, `http://localhost:9999`, and `https://stewfrontend-git-preview-test.vercel.app` receive `ACAO=None`. |
| **B4** | Error handling & config | **PASS** | `docs/staging-qa/b4-errors-config.txt`, `docs/staging-qa/b4-local-sklive-refusal.txt` — malformed JSON `400` JSON, `DELETE /api/health/` `405` JSON, `/admin/` `302` to login, unauth payment `401` JSON, `/api/health/` `200 {"status":"ok"}` (`39.25s` cold start); local `APP_ENV=staging` + `sk_live_` refuses boot with `RuntimeError`. *(Note: unknown URL `/api/nonexistent-404/` returns Django's standard HTML 404 with zero stack/SQL/paths.)* |
| **B5** | Auth & abuse controls | **PARTIAL (Unauth PASS / Auth NEEDS HUMAN)** | `docs/staging-qa/b5-auth-unauth.txt` — non-allowed & `+alias` registrations rejected (`400`); `/api/auth/me/`, `/api/orders/`, `/api/admin/users/` return `401`. **Note:** `/api/admin/diagnostics/client-ip/` returned `404` on live Render (Render is not yet on the latest `staging` commit). Authenticated checks (wrong password timing, 429 lockout, logout replay, 403 role boundaries, IDOR) await `.staging-test-accounts.env`. |
| **B6** | Proxy & `TRUSTED_PROXY_COUNT` | **NEEDS HUMAN** | Requires Render redeploy to latest `staging` (for `/api/admin/diagnostics/client-ip/`), admin account, and temporary `THROTTLE_ANON_PER_MIN=60` two-network test. |
| **B7** | Frontend supply & leakage | **PARTIAL (Old build; SW/storage NEEDS HUMAN)** | `docs/staging-qa/b7-frontend-bundles.txt` — `.js.map` returns `404`, zero `sk_`/`BEGIN PRIVATE KEY` strings, but live bundle `index-0dHfOSup.js` has `noindex_meta_present=False` and `api_urls=[]` (confirming Vercel is serving an old `main` build, not `staging`). SW & `localStorage` checks await `staging` redeploy + login. |
| **B8** | Vercel exposure | **PARTIAL** | `docs/staging-qa/b3-cors.txt` confirms preview origin `https://stewfrontend-git-preview-test.vercel.app` is blocked by API CORS. Human must confirm Vercel **Production Branch = `staging`** and **Deployment Protection** setting. |
| **B9** | Webhook endpoint | **PARTIAL (Reject PASS / Replay NEEDS HUMAN)** | `docs/staging-qa/b9-webhook-reject.txt` — unsigned `POST` → `400 {"ok":false}`, invalid signature → `401 {"ok":false}`. Valid Paystack TEST event replay idempotency awaits Paystack TEST webhook setup. |
| **C1–C9** | Live E2E & OTP delivery | **NEEDS HUMAN** | Awaits `.staging-test-accounts.env` (throwaway customer, vendor, admin accounts) and Paystack TEST webhook registration. |

---

## 3. Findings Table

| ID | Severity | Where Seen | Evidence | Status |
|---|---|---|---|---|
| **STG-01** | **High** | `https://stewfrontend.vercel.app` | `b1-b2-tls-headers.txt`, `b7-frontend-bundles.txt` — Live Vercel site is serving an old `main` build (`Last-Modified: Thu, 26 Nov 2026`, `index-0dHfOSup.js`, missing `vercel.json` headers, missing `noindex`, `api_urls=[]`). | **Open — Needs Human** (Set Vercel Production Branch to `staging`, set `VITE_API_URL=https://stew-backend.onrender.com/api`, `VITE_APP_ENV=staging`, `VITE_PAYSTACK_PUBLIC_KEY=pk_test_...`, and redeploy) |
| **STG-02** | **Medium** | `https://stew-backend.onrender.com` | `b5-auth-unauth.txt` — `/api/admin/diagnostics/client-ip/` returned `404` because Render is running an older commit than `staging`. | **Open — Needs Human** (Trigger Render deploy of `staging` once pushed) |
| **STG-03** | **Low** | `https://stew-backend.onrender.com/api/nonexistent-404/` | `b4-errors-config.txt` — Unmatched `/api/*` paths return Django's default HTML 404 page instead of JSON (no stack trace or secrets leaked). | Accepted / low |

---

## 4. Not Verified Yet
- Authenticated B5 checks (account enumeration timing, 429 lockout + Security tab logging, JWT logout revocation replay, 403 role checks, IDOR across two accounts).
- B6 (`TRUSTED_PROXY_COUNT` calibration and two-network `THROTTLE_ANON_PER_MIN=60` test).
- B7 live service worker & `localStorage` inspection on the `staging` Vercel build.
- B8 human confirmation of Vercel Deployment Protection & Production Branch.
- B9 valid Paystack TEST webhook replay idempotency.
- C1–C9 live Playwright E2E journeys and real-inbox OTP delivery.
