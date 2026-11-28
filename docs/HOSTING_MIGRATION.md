# STEW Production Hosting & Migration Guide (Hostinger KVM VPS)

## 1. Hostinger Plan Assessment (Verified Against Hostinger Documentation)
- **Shared / Cloud Web Hosting:** **Not supported** for STEW's backend. Hostinger shared plans target PHP/WordPress on LiteSpeed/Apache with MySQL/MariaDB, lack root access and systemd control for long-lived `gunicorn` WSGI workers, and do not provide standalone production PostgreSQL.
- **Hostinger KVM VPS (Ubuntu 22.04 / 24.04 LTS):** **Required.** Provides full root SSH access to run PostgreSQL locally, `gunicorn` under `systemd`, `nginx` with Certbot TLS, `ufw`, `fail2ban`, and scheduled cron/systemd timers. Recommended minimum: **KVM 2 (2 vCPU, 8 GB RAM, NVMe)** for production; KVM 1 (1 vCPU, 4 GB RAM) for small initial traffic.

---

## 2. Target Linux VPS Architecture
All config templates live in [`deploy/`](../deploy/) (templates only, no secrets):
1. **OS & Access Hardening:**
   - Dedicated non-root app user `stew` (`/opt/stew/stew_backend`).
   - SSH key-only auth (`PasswordAuthentication no`, `PermitRootLogin no` in `/etc/ssh/sshd_config`).
   - `ufw` firewall allowing **only** `22/tcp`, `80/tcp`, `443/tcp`.
   - `fail2ban` enabled for SSH + `unattended-upgrades` enabled for security patches.
2. **Database (PostgreSQL):**
   - Listen on `127.0.0.1` only (`listen_addresses = 'localhost'` in `postgresql.conf`); never expose `5432` to the internet.
3. **Application Server (`gunicorn` + `systemd`):**
   - Template: [`deploy/stew-gunicorn.service`](../deploy/stew-gunicorn.service).
   - Runs `stew_server.wsgi:application` as user `stew` with `Restart=always`, reading `/etc/stew/stew.env` (`chmod 600`, owned by `root:stew`, outside the git repo — see [`deploy/stew.env.template`](../deploy/stew.env.template)).
   - Bind to `127.0.0.1:8000` (or Unix socket `/run/stew/gunicorn.sock`).
4. **Reverse Proxy (`nginx` + Certbot TLS):**
   - Template: [`deploy/stew-nginx.conf`](../deploy/stew-nginx.conf).
   - TLS via `certbot --nginx` with automatic `certbot.timer` renewal.
   - `client_max_body_size 3M;`, `gzip on;`, `X-Forwarded-Proto $scheme`, `X-Forwarded-For $proxy_add_x_forwarded_for`, `server_tokens off;`, and baseline security headers.
5. **Log Rotation:**
   - Template: [`deploy/stew-logrotate`](../deploy/stew-logrotate) → `/etc/logrotate.d/stew`.

---

## 3. Backups & Restore Rehearsal
- **Automated Daily Backups:** [`deploy/stew-backup.sh`](../deploy/stew-backup.sh) runs `pg_dump -Fc` daily, retains 14–30 days locally, and syncs encrypted/off-server copies (e.g. `rclone` to S3/B2/object storage).
- **Restore Rehearsal (Required Before Launch):**
  ```bash
  createdb -U postgres stew_restore_test
  pg_restore -U postgres -d stew_restore_test --no-owner /var/backups/stew/stew_YYYY-MM-DD.dump
  psql -U postgres -d stew_restore_test -c "SELECT COUNT(*) FROM api_user; SELECT COUNT(*) FROM api_order;"
  dropdb -U postgres stew_restore_test
  ```

---

## 4. Scheduled Jobs (`deploy/stew-cron`)
Install [`deploy/stew-cron`](../deploy/stew-cron) as `/etc/cron.d/stew` (runs as `stew` with `/etc/stew/stew.env`):
- **Every 10 min:** `manage.py expire_unpaid_orders` (releases `Meal.left` stock from unpaid checkouts).
- **Every 15 min:** `manage.py retry_pending_refunds` (retries `refund_pending` orders outside payout batches).
- **Daily (03:15):** `manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600` (prunes expired rate-limit buckets, JWT revocations, and `FailedLoginEvent` rows older than `FAILED_LOGIN_RETENTION_DAYS`).

---

## 5. `TRUSTED_PROXY_COUNT` Calibration
- **nginx directly on the internet:** `nginx` appends 1 entry (`$remote_addr`) to `X-Forwarded-For` → set `TRUSTED_PROXY_COUNT=1`.
- **nginx behind Cloudflare:** Cloudflare appends the client IP and `nginx` appends Cloudflare's edge IP (2 trusted hops) → set `TRUSTED_PROXY_COUNT=2` (or configure `ngx_http_realip_module` with Cloudflare's published IP ranges + `TRUSTED_PROXY_COUNT=1`).
- **Verification:** Before removing the temporary diagnostics endpoint prior to launch, call `GET /api/admin/diagnostics/client-ip/` as an admin and confirm `clientIp` matches your public IP and spoofed `X-Forwarded-For` values are ignored.

---

## 6. Cutover & Rollback Plan
1. **Freeze writes** on staging (or put maintenance notice up).
2. **Export & restore DB** (only if migrating staging data; for a clean production launch, start with an empty DB and run `promote_admin`):
   - `pg_dump -h <render-host> -U <user> -d <db> -Fc -f stew.dump`
   - `pg_restore -d stew_prod stew.dump`
3. **Apply migrations & static check:** `python manage.py migrate --noinput` and `python manage.py check --deploy --fail-level WARNING`.
4. **Update DNS** (`api.<yourdomain>` → VPS IPv4), issue TLS cert via `certbot --nginx`, and start `stew-gunicorn`.
5. **Update env & origins:** Set `APP_ENV=production`, `DEBUG=False`, `BETA_EMAIL_ALLOWLIST=` (empty), fresh `SECRET_KEY`, `ALLOWED_HOSTS=api.<yourdomain>`, `CORS_ALLOWED_ORIGINS` & `CSRF_TRUSTED_ORIGINS` to the live frontend origin, and **LIVE** Paystack keys (`pk_live_...`, `sk_live_...`).
6. **Update Paystack LIVE webhook URL** to `https://api.<yourdomain>/api/payments/webhook/` with `charge.success` and `refund.*` events.
7. **Smoke tests:** `GET /api/health/` → `200`, HTTPS redirect, CORS header check, and one small real GHS 1.00 live end-to-end payment + refund check.
8. **Rollback:** Point DNS / Vercel `VITE_API_URL` back to the previous working origin and restore the pre-cutover DB snapshot if any migration or payment issue occurs.

### Frontend Hosting Options
- **Option A — Keep Frontend on Vercel (Recommended initially):** Update `VITE_API_URL=https://api.<yourdomain>/api`, `VITE_PAYSTACK_PUBLIC_KEY=pk_live_...`, and remove `VITE_APP_ENV=staging` (and `X-Robots-Tag: noindex` in `vercel.json` once ready for indexing), then redeploy.
- **Option B — Self-host Frontend on the same VPS (`nginx`):** Build `dist/` with `VITE_API_URL=https://api.<yourdomain>/api`, serve `/var/www/stew` via `nginx` `try_files $uri /index.html;` with the same security and `Cache-Control` headers from `vercel.json`.

---

## 7. Go-Live Gates Checklist (Human Sign-Off Required)
- [ ] Paystack Live account approved and KYC complete
- [ ] Paystack refund funding / balance behavior understood
- [ ] Legal, Terms, and Privacy pages updated with live operator contact details
- [ ] Vendor payout batch disbursement & reconciliation SOP defined
- [ ] Backup & restore rehearsal completed once on target VPS
- [ ] Uptime monitoring & error tracking (e.g. Sentry / UptimeRobot on `/api/health/`) active
- [ ] **Temporary `GET /api/admin/diagnostics/client-ip/` endpoint removed**
- [ ] `APP_ENV=production`, `DEBUG=False`, `PAYSTACK_ALLOW_MOCK=False`, `BETA_EMAIL_ALLOWLIST=` (empty)
- [ ] Fresh production `SECRET_KEY` generated (`secrets.token_urlsafe(64)`)
- [ ] First admin bootstrapped on empty production DB via `manage.py promote_admin --email <admin@st.knust.edu.gh>`
