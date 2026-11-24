# STEW Backend — Render Staging Deployment Guide

## 1. Render Service Configuration
- **Repository / Branch:** `ElliotSeidu/stew_backend` → branch `staging`
- **Region:** `frankfurt` (closest Render region to Ghana; keep PostgreSQL and Web Service in the same region)
- **Runtime:** Python `3.13.1` (`free` plan for both PostgreSQL and Web Service)
- **WSGI Module:** `stew_server.wsgi:application`
- **Build Command:**
  ```bash
  pip install -r requirements.txt
  ```
- **Start Command:**
  ```bash
  python manage.py migrate --noinput && gunicorn stew_server.wsgi:application --bind 0.0.0.0:$PORT --workers 1 --timeout 120
  ```
- **Health Check Path:** `/api/health/` (unauthenticated, 0 DB queries, returns `{"status": "ok"}`)

> [!IMPORTANT]
> Free Render web services spin down after ~15 minutes of inactivity (first wake-up takes ~60s) and have no interactive shell or cron jobs. Free Render PostgreSQL databases expire **30 days** after creation (14-day grace period).

---

## 2. Environment Variables Table

| Name | Example | Who sets it | Secret? |
|---|---|---|---|
| `PYTHON_VERSION` | `3.13.1` | Render env | No |
| `APP_ENV` | `staging` | Render env | No |
| `DEBUG` | `False` | Render env | No |
| `SECRET_KEY` | `<64+ char random urlsafe string>` | Human (`secrets.token_urlsafe(64)`) | **Yes** |
| `ALLOWED_HOSTS` | `<your-api>.onrender.com` | Render env | No |
| `CORS_ALLOWED_ORIGINS` | `https://stewfrontend.vercel.app` | Render env | No |
| `CSRF_TRUSTED_ORIGINS` | `https://stewfrontend.vercel.app` | Render env | No |
| `DB_ENGINE` | `postgresql` | Render env | No |
| `DB_HOST` | `<internal-render-pg-host>` | Render DB link | No |
| `DB_PORT` | `5432` | Render DB link | No |
| `DB_NAME` | `stew_staging` | Render DB link | No |
| `DB_USER` | `stew_staging_user` | Render DB link | No |
| `DB_PASSWORD` | `<from-render-postgres>` | Render DB link | **Yes** |
| `DB_SSLMODE` | `require` | Render env | No |
| `TRUSTED_PROXY_COUNT` | `1` *(calibrate via Section 6)* | Render env | No |
| `THROTTLE_ANON_PER_MIN` | `1000` | Render env | No |
| `THROTTLE_USER_PER_MIN` | `120` | Render env | No |
| `PAYSTACK_PUBLIC_KEY` | `pk_test_...` | Human (Paystack Test Mode) | No (public) |
| `PAYSTACK_SECRET_KEY` | `sk_test_...` | Human (Paystack Test Mode) | **Yes** |
| `PAYSTACK_ALLOW_MOCK` | `False` | Render env | No |
| `BETA_EMAIL_ALLOWLIST` | *(empty for students, or `a@gmail.com,b@outlook.com`)* | Human (staging only) | No |
| `EMAIL_BACKEND` | `django.core.mail.backends.smtp.EmailBackend` | Render env | No |
| `EMAIL_HOST` | `smtp-relay.brevo.com` | Human (SMTP provider) | No |
| `EMAIL_PORT` | `587` | Human (SMTP provider) | No |
| `EMAIL_HOST_USER` | `<smtp-login>` | Human (SMTP provider) | No |
| `EMAIL_HOST_PASSWORD` | `<smtp-password-or-app-key>` | Human (SMTP provider) | **Yes** |
| `EMAIL_USE_TLS` | `True` | Render env | No |
| `DEFAULT_FROM_EMAIL` | `STEW Staging <noreply@example.com>` | Human (SMTP verified sender) | No |
| `JWT_ACCESS_TOKEN_LIFETIME_HOURS` | `12` | Render env | No |
| `UNPAID_ORDER_TTL_MINUTES` | `30` | Render env | No |
| `FAILED_LOGIN_RETENTION_DAYS` | `30` | Render env | No |
| `FAILED_LOGIN_IP_HOURLY_CAP` | `60` | Render env | No |
| `CUSTOMER_CANCEL_UNTIL_PREP_STARTS` | `True` | Render env | No |
| `CUSTOMER_CANCEL_WINDOW_SECONDS` | `120` | Render env | No |
| `CUSTOMER_PAID_CANCELS_PER_DAY` | `5` | Render env | No |

---

## 3. Paystack TEST Webhook Setup
1. Open the Paystack Dashboard and switch to **Test Mode**.
2. Go to **Settings → API Keys & Webhooks → Test Webhook URL** and set:
   ```text
   https://<your-render-service>.onrender.com/api/payments/webhook/
   ```
3. Enable events:
   - `charge.success`
   - `refund.pending`
   - `refund.processing`
   - `refund.processed`
   - `refund.failed`
   - `refund.needs_attention`

---

## 4. Promoting the First Admin (From Laptop via External DB URL)
1. Register and verify an account on `https://stewfrontend.vercel.app` using your real campus `@st.knust.edu.gh` email.
2. In a **single PowerShell session** inside `stew_backend/` (using Render PostgreSQL's **External Database** host/user/password, `APP_ENV="development"` + `DEBUG="True"` locally so `settings.py` accepts local `.env` flags without modifying local files):
   ```powershell
   $env:APP_ENV="development"
   $env:DEBUG="True"
   $env:PAYSTACK_SECRET_KEY=""
   $env:PAYSTACK_PUBLIC_KEY=""
   $env:DB_ENGINE="postgresql"
   $env:DB_HOST="<render-external-postgres-host>"
   $env:DB_PORT="5432"
   $env:DB_NAME="stew_staging"
   $env:DB_USER="stew_staging_user"
   $env:DB_PASSWORD="<from-render-dashboard>"
   $env:DB_SSLMODE="require"
   .\venv\Scripts\python.exe manage.py promote_admin --email <admin@st.knust.edu.gh>
   ```

> [!CAUTION]
> **NEVER run `manage.py seed_data` against the Render staging (or production) database.** `seed_data` is for local development only and creates dummy accounts/data.

---

## 5. Manual Maintenance Commands & Cadence (Free Tier)
Run from the same PowerShell session configured in Section 4 (for `retry_pending_refunds`, also set `$env:PAYSTACK_SECRET_KEY="<your-sk_test-key>"`):

| Command | Purpose | Recommended Cadence |
|---|---|---|
| `.\venv\Scripts\python.exe manage.py expire_unpaid_orders` | Releases reserved `Meal.left` stock from abandoned unpaid checkouts (`> UNPAID_ORDER_TTL_MINUTES`). | Every 15–30 minutes during active friend testing, and at the end of each session. |
| `.\venv\Scripts\python.exe manage.py retry_pending_refunds` | Retries `refund_pending` orders outside payout batches against Paystack TEST API. | Every 15–30 minutes during active testing, and after each session. |
| `.\venv\Scripts\python.exe manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600` | Prunes expired `RateLimitBucket` rows, expired JWT revocations, and `FailedLoginEvent` rows older than `FAILED_LOGIN_RETENTION_DAYS` (30 days). | Daily (or after each testing day). |

---

## 6. Determining `TRUSTED_PROXY_COUNT` (Temporary Diagnostics Endpoint)
A temporary admin-only endpoint `GET /api/admin/diagnostics/client-ip/` is included on `staging` (returns `{"xffCount": <int>, "clientIp": "<ip>"}` with no raw header values):
1. Log in as the promoted admin and `GET https://<your-render-service>.onrender.com/api/admin/diagnostics/client-ip/` with `Authorization: Bearer <admin-jwt>`.
2. Check `xffCount` (from a normal browser/curl request with no extra `X-Forwarded-For` header). On Render, if `xffCount` is `2` (for example, edge + internal proxy), set `TRUSTED_PROXY_COUNT=1` or `2` depending on which hop appends the real client IP, then confirm `clientIp` matches your public IP (e.g. via `https://api.ipify.org`).
3. **Remove `GET /api/admin/diagnostics/client-ip/` before real production launch.**
