# STEW Pre-Launch Security Review & Remediation Report

**Target System:** STEW (KNUST Campus Food Marketplace — Django REST API + React/Vite PWA)  
**Repositories & Branches:**
- Backend (`stew_backend`): `security/pre-launch` branched from `refactor/stew-cleanup-v2` (`ab2523b`)
- Frontend (`stew`): `security/pre-launch` branched from `refactor/stew-cleanup-v2` (`e93a339`)

---

## 1. Findings Table

| ID | Title | Severity | Location | Proof / Regression Test | Status | Commit |
|---|---|---|---|---|---|---|
| `SEC-01` | UI admin routing & user list checked `user.role === "admin"`, while `AdminUserSerializer` omitted `isAdmin` | High | `stew/src/components/guards.jsx:11`, `stew/src/App.jsx:140`, `stew/src/context/Providers.jsx:121`, `stew/src/pages/auth/Auth.jsx:25,194`, `stew/src/pages/customer/Account.jsx:147,197`, `stew/src/pages/NotFound.jsx:10`, `stew/src/pages/admin/Admin.jsx:990`, `stew/src/pages/vendor/Vendor.jsx:107`, `stew_backend/api/serializers.py:284` | `AdminUnificationMatrixTest.test_matrix_08_admin_users_list` | `fixed` | `4a586a0` (BE), `a5873b8` (FE) |
| `SEC-02` | `ChunkErrorBoundary` called `setState` inside `componentDidUpdate` (`react(no-did-update-set-state)`) | Low | `stew/src/App.jsx:93-98,188` | `npm run lint` (`0` errors, `11` warnings) | `fixed` | `b8ab988` (FE) |
| `SEC-03` | `me_view` `save(update_fields=changed_fields)` omitted `User.updated_at` (`auto_now=True`) | Medium | `stew_backend/api/views.py:628` | `UpdateFieldsSafetyTest.test_me_view_patch_advances_updated_at` | `fixed` | `cac31c2` (BE) |
| `SEC-04` | Frontend mock layer used `admin@` email-prefix heuristics (`startsWith('admin')`) and fell back silently to `MOCK` if `VITE_API_URL` was unset in `PROD`; sourcemaps not explicitly disabled | High | `stew/src/lib/api.js:7-20,141-155,516,526`, `stew/vite.config.js:7-9` | `git grep "startsWith"` + `npm run build` (`sourcemap: false`) | `fixed` | `c578c54` (FE) |
| `SEC-05` | Unverified & suspended (`active=False`) vendor gate bypass: unverified vendor signup defaulted `active=True`, suspended vendors could self-reactivate via `POST /api/vendor/apply/`, edit/publish meals, advance/complete orders, appear in `vendor_detail_view`, and enter payout batches | High | `stew_backend/api/authentication.py:54-79`, `stew_backend/api/views.py:78-87,273-326,617,699-776,825-830,1535-1660,1843` | `VendorGateSecurityTests` (5 tests) | `fixed` | `c2d147e` (BE) |
| `SEC-06` | Missing row locks (`select_for_update`) on order cancel/collect/complete/payout/review, terminal (`cancelled`/`collected`) and unpaid orders accepted prep/meetup/message mutations, duplicate support cases allowed, and support-case refund failed to restore meal stock | Critical | `stew_backend/api/views.py:90-108,1111-1160,1443-1675,1735-1778,1884-2025` | `OrderStateAndConcurrencySecurityTests` (3 tests) | `fixed` | `7bf6e21` (BE) |
| `SEC-07` | `JWTAuthentication` & `/api/auth/login-code/` accepted `verified=False` accounts, OTP lockouts left OTP hash active for later windows, duplicate verified student `reference_id` allowed on register, and `_RATE_LIMIT_CACHE` grew unbounded | High | `stew_backend/api/authentication.py:31`, `stew_backend/api/security.py:70-92`, `stew_backend/api/views.py:251,326,453,470,540` | `AuthAndOtpSecurityTests` (3 tests) | `fixed` | `4119b80` (BE) |
| `SEC-08` | Financial fields stored as `FloatField`, `Order.payment_reference` lacked `unique=True`, and `Meal`/`Order`/`PayoutBatch`/`Review` lacked DB `CheckConstraint`s | High | `stew_backend/api/models.py:111-235`, `stew_backend/api/migrations/0003_decimal_money_and_constraints.py`, `stew_backend/api/serializers.py:87,111-113,171,232`, `stew_backend/api/views.py:121-130,990-1015` | `MoneyPrecisionAndConstraintsTest` (3 tests) + reversible `migrate`/`migrate api 0002` | `fixed` | `e29849d` (BE) |
| `SEC-09` | Missing rate limits on order creation, Paystack init/verify, meetup, reviews, vendor application, and push subscribe; unbounded list querysets; missing `HttpOnly`/`SameSite`/`COOP`/`DATA_UPLOAD_MAX_MEMORY_SIZE` settings | Medium | `stew_backend/api/views.py:111-123,699,738,847,966,1164,1287,1443,1735-2104`, `stew_backend/stew_server/settings.py:191-208` | `RateLimitPaginationAndSettingsSecurityTests` (3 tests) + `manage.py check --deploy` | `fixed` | `52e8d25` (BE) |
| `SEC-10` | Authenticated vendor user without a `Vendor` profile receives zeroed `200` from `GET /api/payouts/` | Low | `stew_backend/api/views.py:1357` | `AdminUnificationMatrixTest.test_matrix_19_payouts_ledger` | `accepted` | Pre-decided design constraint |
| `SEC-11` | Bearer JWT persisted in browser `localStorage` | Low | `stew/src/context/Providers.jsx`, `stew/src/lib/api.js` | Manual inspection (zero `dangerouslySetInnerHTML`, React escaping, strict HTTPS + HSTS) | `accepted` | — |
| `SEC-12` | Multi-worker cache, live payment keys, secrets rotation, backups, and pre-deploy admin audit | High | Production infrastructure & environment variables | — | `manual` | See Section 3 |

---

## 2. Test and Tool Results (Before and After)

| Check / Tool | Before (`refactor/stew-cleanup-v2`) | After (`security/pre-launch`) |
|---|---|---|
| Backend test suite (`python manage.py test api`) | `74 tests in 49.695s — OK` | **`92 tests in 59.751s — OK`** (`18` new security & regression tests added; all failed pre-fix or tested new invariants and pass post-fix) |
| Django migration check (`makemigrations --check --dry-run`) | Up to `0002` | Migration `0003_decimal_money_and_constraints` verified forward -> backward (`migrate api 0002`) -> forward -> **`No changes detected`** |
| Django deployment check (`manage.py check --deploy`) | Local `.env` (`DEBUG=True`): 5 warnings (`W004, W008, W012, W016, W018`); with prod env flags (`DEBUG=False`): `0 issues` | With prod env overrides (`DEBUG=False`, non-placeholder `SECRET_KEY`, `EMAIL_BACKEND=smtp`, `PAYSTACK_ALLOW_MOCK=False`): **`System check identified no issues (0 silenced).`** |
| Frontend linter (`npm run lint`) | `0 errors, 12 warnings` | **`0 errors, 11 warnings`** |
| Frontend production build (`npm run build`) | `dist/assets/index-*.js` ~`402.83 kB`; succeeded | **`dist/assets/index-CgGPDN0Y.js` `402.55 kB` (`gzip: 119.58 kB`), `Orders` `22.22 kB`, `Admin` `23.68 kB`, `Vendor` `38.68 kB`; `built in 2.31s` (`sourcemap: false`)** |
| Frontend dependency audit (`npm audit`) | `6 vulnerabilities (1 low, 5 moderate)` in dev/build dependencies (`fast-uri`, `glob`, `minimatch`, `serialize-javascript`) | **`npm audit --omit=dev`: `found 0 vulnerabilities`** (full `npm audit`: same `6` dev-toolchain advisories, `0` runtime client dependency advisories) |
| Python security CLI scanners (`bandit`, `pip-audit`, `ruff`, `gitleaks`, `trufflehog`) | Not installed in local Windows/venv environment | Not installed; compensated by full manual audit of `api/` & `stew_server/`, `pip list` version review (`Django==6.1.2`, `djangorestframework==3.18.3`, `PyJWT==2.15.1`, `requests==2.34.2`, `django-cors-headers==4.9.0`, `urllib3==2.8.0`), and full `git log --all -p` regex scan for leaked secrets (none found) |

### Migration `0003` Rollback Note
Migration `api/migrations/0003_decimal_money_and_constraints.py` includes a reversible `RunPython` step (`reverse_code=migrations.RunPython.noop`) and schema alterations for `DecimalField`, `Order.payment_reference` unique index, and `CheckConstraint`s. To roll back cleanly if needed:
```bash
python manage.py migrate api 0002
```
All `AlterField` and `AddConstraint` operations reverse back to `FloatField` without dropping table data. If reversing onto SQLite/PostgreSQL after multiple empty-string rows were converted to `NULL`, rows retain valid `NULL` values.

---

## 3. Manual Pre-Launch Checklist (Must Be Completed by Operator)

1. **Admin Rollout Audit (`docs/ADMIN_ROLLOUT.md`):**
   - Run the read-only Django shell query in `docs/ADMIN_ROLLOUT.md` against the production database **before deploying** to verify that all legitimate STEW operators have `is_admin=True` and any legacy `is_staff`/`role='admin'`/`account_type='admin'` accounts without `is_admin=True` are reviewed.
2. **Production Secrets & Configuration (`.env` / Host Env):**
   - Generate a fresh 64+ character `SECRET_KEY` (`python -c "import secrets; print(secrets.token_urlsafe(64))"`).
   - Set `DEBUG=False`, explicit `ALLOWED_HOSTS`, explicit `CORS_ALLOWED_ORIGINS`, and explicit `CSRF_TRUSTED_ORIGINS` (all `https://`).
   - Configure `VITE_API_URL=https://...` in the frontend build environment (`npm run build` fails loudly at runtime if `VITE_API_URL` is unset in `PROD`).
   - Set live `PAYSTACK_PUBLIC_KEY` and `PAYSTACK_SECRET_KEY`, set `PAYSTACK_ALLOW_MOCK=False`, and register the Paystack dashboard webhook URL pointing to `https://<api-domain>/api/payments/webhook/`.
   - Configure transactional SMTP (`EMAIL_BACKEND`, `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS=True`, `DEFAULT_FROM_EMAIL`).
3. **Database Migration, PostgreSQL & Backups:**
   - Provision PostgreSQL (`DB_ENGINE=postgresql`, `DB_SSLMODE=require`), enable automated daily snapshots + point-in-time recovery, and test a restore before launch.
   - Run `python manage.py migrate` and confirm `0003_decimal_money_and_constraints` applies cleanly against staging/production data.
4. **Shared Rate-Limit Cache & Reverse Proxy:**
   - Configure a shared Redis cache (`django-redis` / Django `CACHES`) if running multiple Gunicorn workers or containers (currently `_RATE_LIMIT_CACHE` is in-process memory).
   - Enforce TLS termination and upload body size caps (`client_max_body_size 5m`) in nginx/Caddy/load balancer with `X-Forwarded-Proto: https`.
   - Set `JWT_ACCESS_TOKEN_LIFETIME_HOURS` to a tighter window (e.g. `4` or `12`) if stricter session expiry is desired without disrupting campus student sessions.
   - Configure external uptime monitoring and log alerting (Sentry or structured log alerts on `401`/`403`/`5xx` and Paystack failures).

---

## 4. Residual Risks and Trade-Offs

- **Single-process rate limiting (`_RATE_LIMIT_CACHE`):** Bounds memory at 5,000 tracked buckets per worker, but does not share counters across multiple Gunicorn workers or server instances until backed by Redis.
- **`localStorage` JWT storage (`stew.token`):** Accepted for mobile-first PWA ergonomics. Any future XSS flaw would be able to read the token; mitigated by zero `dangerouslySetInnerHTML`, strict React auto-escaping, `escape()` input sanitization on backend, `X_FRAME_OPTIONS = 'DENY'`, and `SECURE_CONTENT_TYPE_NOSNIFF = True`.
- **Unbounded list response shape compatibility:** List endpoints accept `?limit=&offset=` and cap responses at a default of 200 items (max 500) rather than switching to DRF `{results, next}` objects so all existing React array consumers remain compatible. If any catalog/order table exceeds 200 active items, add cursor/page controls in the frontend.
- **Vendor Payout Batch Settlement:** Creating a `PayoutBatch` transitions eligible `released` orders to paid-batch ledger state in STEW's database; actual Paystack Transfer / MoMo bank disbursement must still be executed and reconciled by the platform operator.
- **Dev-dependency npm advisories:** 6 low/moderate advisories (`fast-uri`, `glob`, `minimatch`, `serialize-javascript`) exist inside Vite/PWA build tooling (`npm audit`); runtime production bundle dependencies have `0` advisories (`npm audit --omit=dev`).

---

## 5. Verdict

**Verdict: `READY WITH CONDITIONS`**

All Critical and High application vulnerabilities identified in the code review have proof regression tests (`92` passing backend tests, `0` frontend lint errors, clean Vite production build, and `0 issues` under `manage.py check --deploy` with production flags). Production launch is **conditional** upon completing every item in **Section 3 (Manual Pre-Launch Checklist)**—specifically:
1. Executing the `docs/ADMIN_ROLLOUT.md` production database audit before deploy;
2. Supplying live Paystack keys, strong `SECRET_KEY`, `DEBUG=False`, HTTPS `ALLOWED_HOSTS`/`CORS_ALLOWED_ORIGINS`/`CSRF_TRUSTED_ORIGINS`, `VITE_API_URL`, and SMTP credentials;
3. Backing PostgreSQL with tested automated backups and running `python manage.py migrate`;
4. Configuring shared Redis rate-limit storage if deploying more than one backend worker process.
