# STEW Staging Deployment Log

No secrets, passwords, API keys, or tokens are ever recorded in this log. Only variable/setting **names** changed are logged.

## Phase 2 & Phase 3 — Vercel & Render Staging Deploy (2026-11-28)
- **Vercel (`stew_frontend` → `https://stewfrontend.vercel.app`):**
  - Updated settings (names only): `Production Branch` (`staging`), confirmed `Deployment Protection` (`Standard Protection` for preview deployments; production public).
  - Paused before redeploy: `VITE_PAYSTACK_PUBLIC_KEY`, `VITE_API_URL`, and `VITE_APP_ENV` are missing in Vercel Production Environment Variables (`STG-01` remains open until `VITE_PAYSTACK_PUBLIC_KEY` is added).
  - Safety note: Browser screenshots from the Vercel subagent were deleted from disk immediately.
- **Render (`stew_backend` → `https://stew-backend.onrender.com`):**
  - Updated settings/env names (names only): `Branch`, `Start Command`, `PYTHON_VERSION`.
  - Verified already-configured allowed non-secret env var names: `APP_ENV`, `DEBUG`, `PAYSTACK_ALLOW_MOCK`, `ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, `CSRF_TRUSTED_ORIGINS`, `THROTTLE_ANON_PER_MIN`, `THROTTLE_USER_PER_MIN`, `JWT_ACCESS_TOKEN_LIFETIME_HOURS`; confirmed `BETA_EMAIL_ALLOWLIST` absent.
  - Manual deploy `dep-dc59a049v7es739mocvg` (`staging` commit `f366f39`) succeeded and is **Live** (`gunicorn 23.0.0`, 0 `DisallowedHost` errors).
  - Live probe (`docs/staging-qa/phase3-render-live.txt`): `GET /api/health/` → `200 {"status":"ok"}`; `GET /api/admin/diagnostics/client-ip/` (unauth) → `401` (**`STG-02` closed**).
  - Safety note: Browser screenshots from the Render subagent were deleted from disk immediately.
