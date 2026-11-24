# STEW Branch Map & Staging Consolidation Report

**Consolidated Branch:** `staging` (tag: `staging-base`)  
**Chosen Tip:** `rc4` (`a6189d6` in `stew_backend`, `aa3cd1e` in `stew`, on `feature/privacy-refunds`)  
**Rationale:** `rc4` is the newest release candidate tag in both repositories and already contains all security, pay-first, privacy, and automatic-refund work (`rc1`–`rc4`).

---

## 1. Backend Repository Inventory (`stew_backend`)

| Name | Kind | Tip Commit | Date | Descends From | Status vs `rc4` / `staging` |
|---|---|---|---|---|---|
| `main` | Local + Remote | `9290439` | 2026-11-10 18:40:26 +0000 | — | Included (`merge-base --is-ancestor` = true) |
| `refactor/stew-cleanup` | Local + Remote | `b3b90e1` | 2026-11-16 23:19:39 +0000 | `main` (`9290439`) | **SUPERSEDED — NOT MERGED** (contains `6bebe3b`) |
| `backup/stew-cleanup-before-history` | Tag | `b3b90e1` | 2026-11-16 23:19:39 +0000 | `main` (`9290439`) | **SUPERSEDED — NOT MERGED** (same tip as `refactor/stew-cleanup`) |
| `refactor/stew-cleanup-v2` | Local | `ab2523b` | 2026-11-17 00:43:40 +0000 | `main` (`9290439`) | Included (`merge-base --is-ancestor` = true) |
| `security/pre-launch` | Local | `4fcfb4b` | 2026-11-17 01:57:19 +0000 | `refactor/stew-cleanup-v2` | Included (`merge-base --is-ancestor` = true) |
| `security/final` | Local + Remote | `c22b900` | 2026-11-17 13:37:37 +0000 | `security/pre-launch` | Included (`merge-base --is-ancestor` = true) |
| `security/release` | Local + Remote | `1319ebe` | 2026-11-18 21:29:34 +0000 | `security/final` | Included (`merge-base --is-ancestor` = true) |
| `security/rc1` / `rc1` | Local + Remote + Tag | `cf5e0c3` | 2026-11-18 23:38:05 +0000 | `security/release` | Included (`merge-base --is-ancestor` = true) |
| `feature/pay-first` / `rc2` | Local + Tag | `7101e3f` | 2026-11-23 23:54:05 +0000 | `rc1` (`cf5e0c3`) | Included (`merge-base --is-ancestor` = true) |
| `rc3` | Tag | `27d8f5c` | 2026-11-24 03:33:14 +0000 | `rc2` (`7101e3f`) | Included (`merge-base --is-ancestor` = true) |
| `feature/privacy-refunds` / `rc4` | Local + Tag | `a6189d6` | 2026-11-24 04:22:23 +0000 | `rc3` (`27d8f5c`) | **Tip (`rc4`)** |
| `chore/render-staging` | Local + Remote | `4baa6d4` | 2026-11-24 11:40:06 +0000 | `rc4` (`a6189d6`) | **REAL CODE — NOT IN `rc4`** (left out for human decision) |
| `staging` / `staging-base` | Local + Remote + Tag | — | 2026-11-24 | `rc4` (`a6189d6`) | Consolidated staging branch (`rc4` + clean docs) |

---

## 2. Frontend Repository Inventory (`stew`)

| Name | Kind | Tip Commit | Date | Descends From | Status vs `rc4` / `staging` |
|---|---|---|---|---|---|
| `main` | Local + Remote | `3676264` | 2026-11-10 18:39:14 +0000 | — | Included (`merge-base --is-ancestor` = true) |
| `refactor/stew-cleanup` | Local + Remote | `ac9fdaa` | 2026-11-16 20:12:02 +0000 | `main` (`3676264`) | **SUPERSEDED — NOT MERGED** |
| `backup/stew-cleanup-before-history` | Tag | `ac9fdaa` | 2026-11-16 20:12:02 +0000 | `main` (`3676264`) | **SUPERSEDED — NOT MERGED** |
| `refactor/stew-cleanup-v2` | Local | `e93a339` | 2026-11-17 00:47:42 +0000 | `main` (`3676264`) | Included (`merge-base --is-ancestor` = true) |
| `security/pre-launch` | Local | `c578c54` | 2026-11-17 01:26:05 +0000 | `refactor/stew-cleanup-v2` | Included (`merge-base --is-ancestor` = true) |
| `security/final` | Local + Remote | `5068e6d` | 2026-11-17 13:18:41 +0000 | `security/pre-launch` | Included (`merge-base --is-ancestor` = true) |
| `security/rc1` / `rc1` | Local + Remote + Tag | `38a3478` | 2026-11-18 23:33:08 +0000 | `security/final` | Included (`merge-base --is-ancestor` = true) |
| `feature/pay-first` / `rc2` | Local + Tag | `09d7519` | 2026-11-23 23:49:51 +0000 | `rc1` (`38a3478`) | Included (`merge-base --is-ancestor` = true) |
| `rc3` | Tag | `2408107` | 2026-11-24 03:35:38 +0000 | `rc2` (`09d7519`) | Included (`merge-base --is-ancestor` = true) |
| `feature/privacy-refunds` / `rc4` | Local + Tag | `aa3cd1e` | 2026-11-24 04:03:24 +0000 | `rc3` (`2408107`) | **Tip (`rc4`)** |
| `chore/render-staging` | Local + Remote | `e52f36d` | 2026-11-24 04:58:23 +0000 | `rc4` (`aa3cd1e`) | **REAL CODE — NOT IN `rc4`** (left out for human decision) |
| `staging` / `staging-base` | Local + Remote + Tag | — | 2026-11-24 | `rc4` (`aa3cd1e`) | Consolidated staging branch (identical to `rc4`) |

---

## 3. Extra Commit Classification (`rc4..branch`)

### A. SUPERSEDED (Excluded from `staging`)
- **`stew_backend` `refactor/stew-cleanup` & `backup/stew-cleanup-before-history`:**
  - `1b50ae6` — earlier refactor commit replaced by `refactor/stew-cleanup-v2`
  - `6bebe3b` — widening `_is_admin_user` helper (**explicitly excluded**; `git merge-base --is-ancestor 6bebe3b staging` = `False`)
  - `b3b90e1` — narrowing revert of `6bebe3b`, superseded by `refactor/stew-cleanup-v2` (`ab2523b`)
- **`stew` `refactor/stew-cleanup` & `backup/stew-cleanup-before-history`:**
  - `766ff51`, `ac9fdaa` — superseded by `refactor/stew-cleanup-v2` (`e93a339` → `5097136`)

### B. REAL CODE Not in `rc4` (Left Out — Human Decision Required)
`chore/render-staging` was branched from `rc4` in both repos to prepare Render Blueprints and staging-only controls. It is **not** merged into `staging` so `staging` stays pure `rc4` until you decide whether to fast-forward/merge `chore/render-staging` onto `staging` for Render deployment:
- **`stew_backend` (`rc4..chore/render-staging`):**
  - `1b5c66b` — `APP_ENV` (`production` default, `staging`, `development`) + `validate_runtime_settings` startup guards
  - `3d2adaf` — `BETA_EMAIL_ALLOWLIST` (staging-only) + canonical `is_allowed_email`
  - `ae03a8d` — unauthenticated `GET /api/health/`
  - `a6ab219` — `promote_admin --email` management command
  - `8e6aa9c` — `gunicorn==23.0.0` + `render.yaml` (`stew-db-staging`, `stew-api-staging`)
  - `68e2bf5`, `f43552d`, `4baa6d4` — `docs/RENDER_DEPLOY.md` and `docs/DEPLOY_LOG.md`
- **`stew` (`rc4..chore/render-staging`):**
  - `d70a4e4` — `StagingBanner` (`VITE_APP_ENV=staging`), `<meta name="robots" content="noindex, nofollow" />`, `dist/robots.txt`
  - `e52f36d` — `render.yaml` (`stew-web-staging` static site Blueprint)

### C. Untracked / Uncommitted Files Audit (`stew_backend`)
- `.gitignore`: restored local dirty addition of `docs/` (`git checkout -- .gitignore`).
- `docs/OPUS_SECOND_PASS.md` (226 lines) & `docs/browser-qa/p1-vendor-apply-no-id.png` (18,945 bytes): scanned for secrets, tokens, OTP codes, and personal data — **clean**; committed on `staging` (`3442da5`).
- `docs/STEW_HUMAN_ACTION_CHECKLIST.pdf` (418 KB) & `docs/STEW_SECURITY_ACHIEVEMENTS_REPORT.pdf` (568 KB): large generated PDFs left untracked on disk and excluded locally via `.git/info/exclude` (`docs/*.pdf`).

---

## 4. Verification Summary (`staging`)

- **Clean tree & tracked files:** `git status --short` clean in both repos; `git ls-files` confirmed zero tracked `.env`, `db.sqlite3`, `node_modules`, `dist`, `venv`, or key/credential files.
- **Migrations:**
  - `makemigrations --check --dry-run` → `No changes detected`
  - `showmigrations` order: `admin.0001..0003`, `api.0001_initial`, `api.0002_alter_vendor_rating`, `api.0003_decimal_money_and_constraints`, `api.0004_ratelimitbucket`, `api.0005_failed_login_event`, `auth.0001..0012`, `contenttypes.0001..0002`, `sessions.0001_initial`.
  - Empty PostgreSQL 16 DB (`stew_mig_test`): all 23 migrations applied cleanly from scratch, rolled back 1 step (`api 0004_ratelimitbucket`), and re-applied (`api.0005_failed_login_event`) cleanly.
- **Backend tests:**
  - SQLite: `167` tests passed (`OK`, `skipped=4` PG16-only concurrency tests)
  - PostgreSQL 16: `167` tests passed (`OK`, `0` skipped)
  - `manage.py check --deploy --fail-level WARNING` (prod-style env vars): `System check identified no issues (0 silenced)` (exit `0`)
- **Frontend:**
  - `npm run lint`: `0` errors, `11` pre-existing warnings
  - `npm run build` with `VITE_API_URL=https://api.stew-staging.example.com/api`: succeeded (`dist/` + `dist/sw.js`)
  - `npm run build` with `VITE_API_URL=''`: failed as expected (`[STEW BUILD ERROR] VITE_API_URL is missing`)
- **Security & dependency scans:**
  - `gitleaks` (`stew_backend` `staging`): 2 known false positives only (`('api', '0004_ratelimitbucket')` in `0005_failed_login_event.py:9` and `('api', '0002_alter_vendor_rating')` in `0003_decimal_money_and_constraints.py`); 0 real leaks.
  - `gitleaks` (`stew` `staging`): 35 commits scanned, `no leaks found`.
  - `pip-audit -r requirements.txt`: `No known vulnerabilities found`.
  - `npm audit --omit=dev`: `found 0 vulnerabilities`.

---

## 5. Promotion Plan (For Later — Do Not Run Yet)

Once `staging` has been tested by friends and any fixes are committed on `staging`:
1. Fast-forward `main` to `staging` in both repos:
   ```powershell
   git checkout main
   git merge --ff-only staging
   ```
2. Tag `v0.1.0` on `main` in both repos (`git tag -a v0.1.0 -m "STEW v0.1.0"`).
3. Create a `production` branch from `main` in both repos (`git checkout -b production main`) and push `main`, `production`, and `v0.1.0`.
