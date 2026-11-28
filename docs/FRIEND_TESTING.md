# STEW Staging — Friend-Testing Safety Kit

**App URL:** `https://stewfrontend.vercel.app`  
**API URL:** `https://stew-backend.onrender.com`

---

## Part 1 — For Friend Testers

### 1. What This Test Is (No Real Money)
- This is a **TEST environment** for STEW running in **Paystack Test Mode**.
- **No real money** is charged. Use **only** the test cards / test Mobile Money numbers shown on Paystack's checkout screen or Paystack's official *Test payments* documentation — **never** enter a real bank card or real MoMo PIN.
- **Safety rules:**
  - **Do NOT reuse your real password** from Gmail, KNUST portals, banking, or any other site.
  - **Do NOT enter real personal data** (you may use a throwaway name/phone format like `0240000001`).
  - **Admin chat review notice:** *"Messages in this chat may be reviewed by STEW admins for safety and security."*
- **First-load delay (~60s):** The staging API runs on a free Render instance that sleeps after ~15 minutes of inactivity. If the app shows a loading state on your first visit, wait up to **60 seconds** and retry once if needed.

### 2. Which Emails Can Register
- **KNUST students:** Any valid `@st.knust.edu.gh` email address.
- **Non-campus testers (if invited):** Only exact lowercase addresses explicitly added to `BETA_EMAIL_ALLOWLIST` by the operator.

### 3. 10-Minute Role Test Scripts

#### A. Customer (~10 min)
1. Sign up at `https://stewfrontend.vercel.app/app/signup` → enter the 6-digit email OTP → log in.
2. Browse kitchens on **Home** / **Discover** → add a meal to your tray → checkout and complete a **Paystack Test** payment.
3. Open **Orders**: confirm you see your **6-digit handoff code** (keep it private until collection), propose/confirm a meetup, and send a chat message.
4. Optional cancel test: place a second test order and cancel it **before** the vendor starts preparing it (should trigger an automatic test-mode refund).
5. On a collected order, submit a rating/review.

#### B. Vendor (~10 min)
1. Sign up with account type **Vendor** → verify email OTP → wait for the operator/admin to approve your kitchen.
2. Open **Vendor → Menu** and add 1–2 test meals with stock (e.g., `5`).
3. Confirm an **unpaid** customer order does **not** appear in your vendor dashboard.
4. Once a customer completes a **Paystack Test** payment, confirm the order appears with *"Received N min ago"*, advance prep stages (`Preparing` → `Ready`), and complete handoff by entering the customer's 6-digit code.

#### C. Dual Account (`both`, ~10 min)
1. Sign up with account type **Both**, verify email, and get vendor approval.
2. Verify you can switch between buying from another kitchen and managing your own kitchen, and that you **cannot** order from your own kitchen.

### 4. Bug Report Template
```text
- Role & Device (e.g., Customer, Android Chrome / iPhone Safari):
- Route / Screen (e.g., /app/orders):
- Steps to reproduce:
- Expected vs Actual behavior:
- Approximate time (GMT) & screenshot (redact any email/OTP/code):
```

### 5. Feedback Questions
1. Did the OTP email arrive within 1 minute, and did it land in Inbox or Spam?
2. Was anything confusing during checkout, Paystack test payment, or handoff?
3. Did any screen look cramped or cut off on your phone?
4. What felt slow, broken, or missing?

---

## Part 2 — For the Human Operator

### 1. Before & During Testing Sessions
- **Wake the API** 2 minutes before friends start: open `https://stew-backend.onrender.com/api/health/` and wait for `{"status":"ok"}`.
- **Approve friend vendors:** Log in as Admin → **Vendors** → approve with a `verificationMethod`.
- **View Render logs:** Render Dashboard → `stew-backend` → **Logs** (never share raw env vars or secrets).

### 2. Running Commands from Your Laptop Against Render PostgreSQL
Free Render web services have no interactive shell or cron jobs. Open PowerShell in `stew_backend/` with Render PostgreSQL's **External Database** details:
```powershell
$env:APP_ENV="development"
$env:DEBUG="True"
$env:PAYSTACK_SECRET_KEY=""
$env:PAYSTACK_PUBLIC_KEY=""
$env:DB_ENGINE="postgresql"
$env:DB_HOST="<render-external-host>"
$env:DB_PORT="5432"
$env:DB_NAME="<render-generated-db-name>"
$env:DB_USER="<render-db-user>"
$env:DB_PASSWORD="<from-render-dashboard>"
$env:DB_SSLMODE="require"
```
Then run as needed:
- **Promote an admin:** `.\venv\Scripts\python.exe manage.py promote_admin --email <admin@st.knust.edu.gh>`
- **Release stock from abandoned unpaid orders (every 15–30 min during sessions):** `.\venv\Scripts\python.exe manage.py expire_unpaid_orders`
- **Retry pending refunds (set `$env:PAYSTACK_SECRET_KEY="<sk_test_...>"` first):** `.\venv\Scripts\python.exe manage.py retry_pending_refunds`
- **Prune expired rate limits, JWT revocations & 30-day failed logins (daily):** `.\venv\Scripts\python.exe manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600`
- **Reset non-admin test data between rounds (requires `APP_ENV="staging"`, `DEBUG="False"`):**
  ```powershell
  $env:APP_ENV="staging"; $env:DEBUG="False"; $env:PAYSTACK_ALLOW_MOCK="False"
  $env:SECRET_KEY="<64-char-key>"
  .\venv\Scripts\python.exe manage.py reset_test_data              # dry run
  .\venv\Scripts\python.exe manage.py reset_test_data --apply --i-understand
  ```
- **NEVER run `manage.py seed_data` against Render.**

### 3. Free Database 30-Day Expiry & Backup (`pg_dump`)
- Render's free PostgreSQL database **expires 30 days after creation** (with a 14-day grace period).
- Export a full backup before expiry over the external connection:
  ```powershell
  $env:PGPASSWORD="<from-render-dashboard>"
  pg_dump -h <render-external-host> -p 5432 -U <render-db-user> -d <render-generated-db-name> -Fc -f stew_staging_backup.dump
  ```
