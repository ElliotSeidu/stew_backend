# Render Staging Deployment Guide (`chore/render-staging`)

## Architecture & Region
- **Region:** `frankfurt` (closest Render region to Ghana; API and PostgreSQL database must be in the same region).
- **Backend Blueprint (`stew_backend/render.yaml`):**
  - `stew-db-staging` — Render PostgreSQL (`free` plan)
  - `stew-api-staging` — Python 3.13.1 Web Service (`free` plan, `gunicorn stew_server.wsgi:application`, health check `/api/health/`)
- **Frontend Blueprint (`stew/render.yaml`):**
  - `stew-web-staging` — Static Site (`npm ci && npm run build`, publishes `dist/`, SPA rewrite `/* -> /index.html`, `X-Robots-Tag: noindex, nofollow`, `Content-Security-Policy-Report-Only`, `Cache-Control` rules)

## Render Free-Tier Facts
- Free web services spin down after ~15 minutes of inactivity; the first wake-up request can take up to ~60 seconds.
- Free PostgreSQL databases expire **30 days** after creation and are deleted after a 14-day grace period.
- Free web services have **no interactive shell** and **no one-off jobs**; Render Cron Jobs require a paid instance.

## Local Development Note (`APP_ENV`)
`stew_server/settings.py` defaults `APP_ENV` to `production` and refuses to boot when `DEBUG=True` outside `APP_ENV=development`. For local development, ensure your untracked local `stew_backend/.env` contains:
```env
APP_ENV=development
```
(Or set `$env:APP_ENV="development"` in PowerShell for the current shell session.)

## Promoting an Admin (`promote_admin`)
1. Register and verify an account with a real campus `@st.knust.edu.gh` email.
2. Promote it using `promote_admin --email <email>`:
   - **On a free-tier web service (no Render shell):** run locally from `stew_backend/` using Render's **External Database URL** (from the `stew-db-staging` dashboard). Because `settings.py` loads local `.env` for any unset variables, explicitly override local dev flags (`DEBUG`, `PAYSTACK_ALLOW_MOCK`, `EMAIL_BACKEND`, `SECRET_KEY`, `ALLOWED_HOSTS`):
     ```powershell
     $env:APP_ENV="staging"
     $env:DEBUG="False"
     $env:PAYSTACK_ALLOW_MOCK="False"
     $env:EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend"
     $env:SECRET_KEY="<from-render-dashboard-or-generated-key>"
     $env:ALLOWED_HOSTS="<your-api-host>.onrender.com"
     $env:DB_ENGINE="postgresql"
     $env:DB_HOST="<external-host>"
     $env:DB_PORT="5432"
     $env:DB_NAME="stew_staging"
     $env:DB_USER="stew_staging_user"
     $env:DB_PASSWORD="<from-render-dashboard>"
     $env:DB_SSLMODE="require"
     .\venv\Scripts\python.exe manage.py promote_admin --email <admin@st.knust.edu.gh>
     ```
   - **On a paid instance (with Render shell):**
     ```bash
     python manage.py promote_admin --email <admin@st.knust.edu.gh>
     ```

## Manual Maintenance Commands (When Cron Jobs Are Not Purchased)
Run with the same staging environment block above (for `retry_pending_refunds`, also set `$env:PAYSTACK_SECRET_KEY="<your-staging-sk_test-key>"`):
- `python manage.py expire_unpaid_orders` — releases reserved `Meal.left` stock from abandoned unpaid checkouts (without this cron, unpaid orders hold stock until this command runs).
- `python manage.py retry_pending_refunds` — retries `refund_pending` orders outside payout batches.
- `python manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600` — prunes expired rate-limit buckets, JWT revocations, and `FailedLoginEvent` rows older than `FAILED_LOGIN_RETENTION_DAYS` (30).
