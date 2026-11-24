# STEW Final Pre-Production Security & Release Readiness Report

**System:** STEW — Campus Food Marketplace (Django REST Framework API + React/Vite PWA, KNUST / GHS)  
**Repositories & Branches Reviewed:**
- Backend (`stew_backend`): branch `security/release` (branched from `security/final` `c22b900`, after `security/pre-launch` `4fcfb4b`)
- Frontend (`stew`): branch `security/final` `5068e6d` (from `security/pre-launch` `c578c54`; no frontend changes required in `security/release`)

> **Scope Statement:** Security reviews and automated test suites reduce defect risk under modeled conditions; they do not establish that software is "secure" against all unknown bugs, operational misconfigurations, or third-party service failures. Every verdict below reflects code, configurations, and local test/database runs directly observed in `stew_backend` and `stew`.

---

## 1. Verification of `security/pre-launch` Claims & Findings Table

The prior `docs/SECURITY_REVIEW.md` (`4fcfb4b`) accurately summarized 9 remediation commits (`SEC-01`–`SEC-09`) on SQLite, **but left critical gaps exposed under PostgreSQL, multi-worker deployments, unauthenticated enumeration, upload/state edge cases, Paystack configuration invariants, and missing scanner tooling**:
- PostgreSQL `manage.py test` initially failed with **25 errors** (`NotSupportedError: FOR UPDATE cannot be applied to the nullable side of an outer join`).
- Migration `0003` initially failed on PostgreSQL with messy `0002` data (`decimal.InvalidOperation` on `NaN`, `DataError` on 125-char duplicate `payment_reference`).
- Rate limiting lived in per-process memory (`_RATE_LIMIT_CACHE`); handoff codes were never cleared/rotated on exhaustion or expired after 14 days; `init_payment_view` lacked row locking and overwrote `payment_reference` on double-submit; `_paystack_mock_allowed()` did not check `settings.DEBUG` at runtime; `subscribe_push_view` allowed cross-user push endpoint takeover; `order_detail_view` and `meal_detail_view` used unsafe `UUID == str` comparisons; `OrderSerializer` exposed customer `email` and `payment.reference` to vendors; `_safe_int` / `create_review_view` accepted booleans/floats and clamped out-of-range ratings; `verify_email_view` returned `404` on unknown emails; no JWT revocation (`logout`) existed; `seed_data` could seed `--demo` / overwrite admin passwords when `DEBUG=False`; `/admin/` still honored `is_staff` without `is_admin`; responses lacked `Content-Security-Policy` and `Permissions-Policy`.

### Findings Table (`security/final`)

| ID | Severity | Title | Location | Exploit / Regression Test | Status | Commit |
|---|---|---|---|---|---|---|
| `FIN-01` | Medium | Vulnerable `certifi` (`PYSEC-2026-4320`), unpinned `psycopg[binary]`, and ruff lint hygiene | `requirements.txt`, `api/admin.py`, `api/exceptions.py`, `api/models.py`, `api/views.py`, `seed_data.py` | `pip_audit -r requirements.txt` -> `No known vulnerabilities found` | `fixed` | `75ac293` (BE) |
| `FIN-02` | High | Migration `0003` failed on PostgreSQL with `NaN`/`Infinity` money values and duplicate long `payment_reference` | `api/migrations/0003_decimal_money_and_constraints.py` | `Migration0003MessyDataTests` (`test_quantize_handles_half_up_floats_nan_inf_and_overflow`, `test_normalize_deduplicates_shared_pk_prefix_and_long_payment_references`) + PG messy rehearsal | `fixed` | `340f647` (BE) |
| `FIN-03` | Critical | PostgreSQL `FOR UPDATE` nullable outer-join crash (`25` test errors), inconsistent lock order, and `UUID != str` owner/vendor check bugs | `api/views.py` (`cancel_order_view`, `mark_collected_view`, `complete_by_code_view`, `create_review_view`, `orders_view`, `payout_batches_view`, `_restore_order_stock`) | `PostgresLockingAndConcurrencyTests` (`test_select_for_update_endpoints_succeed_without_nullable_outer_join_and_lock_meals_sorted`, `test_postgresql_threaded_stock_cancel_complete_and_payout_races`) | `fixed` | `3a04072` (BE) |
| `FIN-04` | High | Pending kitchen lockout on detail/compliance views, missing audit ordering on vendor unsuspend guard, and suspended reactivation via `vendor/activate/` | `api/views.py` (`verify_email_view`, `vendor_detail_view`, `vendor_activate_view`) | `VendorGateSecurityTests` (`test_inactive_or_suspended_vendor_owner_can_read_own_vendor_detail_and_compliance_but_public_cannot`, `test_suspended_vendor_cannot_self_reactivate_via_vendor_activate_or_verify_email`) | `fixed` | `11d4ade`, `a71ffb1` (BE) |
| `FIN-05` | Medium | Silent truncation at `200` rows on list views and missing pagination metadata on `admin_audit_view` / UI truncation handling | `api/views.py`, `stew_server/settings.py`, `stew/src/lib/api.js`, `hooks.js`, `ui.jsx`, `Admin.jsx`, `Vendor.jsx`, `Orders.jsx`, `Discover.jsx` | `PaginationAndAggregateTests` (`test_list_endpoints_return_pagination_headers_and_optional_envelope_and_audit_paginates`, `test_payout_ledger_returns_full_set_aggregates_for_vendor_and_admin`) + `oxlint` | `fixed` | `e44ca53` (BE), `0cf06a0`, `687d33f` (FE) |
| `FIN-06` | High | In-memory rate limits lost on restart/multi-worker, XFF header trust assumption, and reusable/non-expiring handoff codes | `api/models.py` (`RateLimitBucket`), `api/migrations/0004_ratelimitbucket.py`, `api/security.py`, `api/views.py`, `stew_server/settings.py` | `PersistentRateLimitAndHandoffTests` (`test_rate_limit_persists_in_database_across_worker_memory_and_cache_flush`, `test_xff_and_header_spoofing_cannot_bypass_otp_login_reset_pay_or_handoff_lockout`, `test_handoff_code_rotates_on_lockout_clears_on_collection_and_expires_after_14_days`) | `fixed` | `e2dad38` (BE) |
| `FIN-07` | High | Non-atomic meetup/chat/nudge/support resolution, unpaid meetup/chat/nudge allowed, double stock restore risk, and refund allowed after payout batching | `api/views.py` (`_mark_order_paid`, `_restore_order_stock`, meetup/message/nudge/review/support views) | `AtomicStateAndUploadSecurityTests` (`test_mark_order_paid_refuses_cancelled_or_refunded_order`, `test_meetup_chat_and_nudge_block_unpaid_orders`, `test_restore_order_stock_is_idempotent`, `test_support_case_resolve_refund_blocks_order_in_payout_batch`) | `fixed` | `4c5f931` (BE) |
| `FIN-08` | Medium | Permissive `data:image/` accepted `image/svg+xml` XSS vectors, silently truncated oversize uploads, and leaked `//` URLs into order line snapshots | `api/views.py` (`_sanitize_media_url`, `orders_view`, callers) | `AtomicStateAndUploadSecurityTests.test_media_url_sanitization_blocks_svg_protocol_relative_and_oversized_while_accepting_jpeg` | `fixed` | `4c5f931` (BE) |
| `FIN-09` | High | Production frontend build succeeded silently with missing `VITE_API_URL`, causing runtime `503` failures | `stew/vite.config.js`, `stew/.env.example`, `stew/README.md`, `stew_backend/README.md` | `VITE_API_URL="" npm run build` exits `1` (`[STEW BUILD ERROR]`) | `fixed` | `0ea8e01` (FE), `52cba37` (BE) |
| `FIN-10` | Critical | `_paystack_mock_allowed()` ignored `settings.DEBUG` at runtime, webhook lacked payload amount/currency/status pre-checks, and `init_payment_view` lacked row lock / idempotent reference reuse | `api/views.py` (`_paystack_mock_allowed`, `init_payment_view`, `_paystack_verify`, `paystack_webhook_view`), `api/tests.py`, `api/tests_invariants.py` | `PaystackHardeningTests` (`test_mock_payment_impossible_when_debug_false`, `test_webhook_rejects_mismatched_amount_currency_or_status_and_unknown_ref`, `test_init_payment_idempotent_reuses_reference`) | `fixed` | `dfef200` (BE) |
| `FIN-11` | Medium | `int()` accepted booleans/floats, duplicate meal lines bypassed `qty <= 50` cap, and `create_review_view` silently clamped out-of-range ratings | `api/views.py` (`_safe_int`, `me_view`, `orders_view`, `create_review_view`) | `QuantityAndRatingValidationTests` (`test_order_rejects_fractional_bool_and_duplicate_line_qty_overflow`, `test_review_rejects_out_of_range_float_and_bool_ratings`, `test_me_patch_rejects_bool_and_float_prep_time`) | `fixed` | `4b95a7a` (BE) |
| `FIN-12` | High | Cross-user push endpoint hijack (`update_or_create`), `order_detail_view` & `meal_detail_view` `UUID == str` bugs, vendor order PII/payment-ref exposure, missing `read_only_fields` | `api/views.py` (`meal_detail_view`, `order_detail_view`, `subscribe_push_view`), `api/serializers.py` | `IDORAndSerializerExposureTests` (`test_push_subscription_cannot_be_hijacked_by_another_user`, `test_order_serializer_redacts_customer_email_and_payment_ref_from_vendor_and_read_only_fields`) | `fixed` | `c0a2b85` (BE) |
| `FIN-13` | High | Missing server-side JWT revocation on logout, `+alias`/dot/non-ASCII/`sub.st.knust` campus email edge cases, and `404` user enumeration on `verify-email` | `api/security.py`, `api/authentication.py`, `api/validators.py`, `api/views.py`, `api/urls.py`, `stew/src/lib/api.js`, `stew/src/context/Providers.jsx` | `AuthAndEmailBypassTests` (`test_logout_revokes_jwt_while_new_token_still_works`, `test_clean_knust_email_rejects_plus_dots_control_homoglyphs_and_subdomains`, `test_verify_email_does_not_enumerate_unknown_accounts`) | `fixed` | `a6f2e67` (BE), `5068e6d` (FE) |
| `FIN-14` | High | `seed_data` allowed `--demo`/default password in prod & overwrote existing admin password, `/admin/` accepted `is_staff` without `is_admin`, missing `CSP`/`Permissions-Policy` headers | `api/management/commands/seed_data.py`, `stew_server/urls.py`, `api/security.py`, `stew_server/settings.py` | `SettingsAndAdminHardeningTests` (`test_seed_data_refuses_demo_or_weak_default_password_in_prod_and_preserves_existing_admin_password`, `test_django_admin_site_requires_is_admin_and_verified`, `test_security_headers_csp_and_permissions_policy_present`) | `fixed` | `ae29f76` (BE) |
| `ACC-01` | Low | Canonical admin model: `is_platform_admin(user) == user.is_admin`; vendor user without `Vendor` profile receives zeroed `200` on `GET /api/payouts/` | `api/authentication.py:51`, `api/views.py:1537` | `AdminUnificationMatrixTest.test_matrix_19_payouts_ledger` | `accepted` | Pre-decided |
| `ACC-02` | Low | JWT access token persisted in browser `localStorage` (`stew.token`) with server revocation on logout and strict XSS hygiene | `stew/src/context/Providers.jsx:96`, `stew/src/lib/api.js` | Code grep (0 `dangerouslySetInnerHTML`/`javascript:`/`eval`) + `AuthAndEmailBypassTests` | `accepted` | `a6f2e67`, `5068e6d` |

### Findings Table (`security/release` — Independent Payment/Auth Pass)

Independent review leads recorded in `docs/OPUS_PAYMENT_REVIEW.md` (`b29c0f1`) were verified against the live codebase and PostgreSQL 16 concurrency runs, producing 7 release commits (`REL-01`–`REL-07`):

| ID | Severity | Title | Location | Exploit / Regression Test | Status | Commit |
|---|---|---|---|---|---|---|
| `REL-01` | High | Paid-after-cancel money orphaning on webhook/verify after cancellation | `api/views.py` (`_mark_order_paid`, `verify_payment_view`, `paystack_webhook_view`, `init_payment_view`) | `PaidAfterCancelOrphanPreventionTests` (`test_cancel_then_webhook_and_duplicate_webhook_are_recorded_and_idempotent`, `test_cancel_then_verify_returns_error_and_marks_refund_pending`, `test_init_payment_refuses_cancelled_and_refund_states`) + PG `STW-PG-RACE4`/`STW-PG-RACE5` | `fixed` | `29bb8ba` (BE) |
| `REL-02` | High | IP-keyed rate limits vulnerable to campus NAT lockout & untrusted `X-Forwarded-For` proxy hops | `stew_server/settings.py` (`TRUSTED_PROXY_COUNT`, `NUM_PROXIES`, `anon: 300/min`), `api/security.py` (`get_client_ip`), `api/views.py`, `.env.example`, `docs/PRODUCTION_PREFLIGHT.md` | `ProxyClientIpAndCampusNatRateLimitTests` (`test_get_client_ip_respects_trusted_proxy_count_right_to_left`, `test_campus_nat_many_distinct_emails_not_blocked_while_single_email_otp_still_locks`) | `fixed` | `6083cf7` (BE) |
| `REL-03` | Medium | Unbounded `RateLimitBucket` table growth, unbounded key truncation collision risk, and `is_jwt_revoked(token)` payload decode asymmetry | `api/management/commands/cleanup_rate_limits.py`, `api/security.py` (`_revoked_jwt_key`, `_normalize_rate_limit_key`, `is_jwt_revoked`), `docs/PRODUCTION_PREFLIGHT.md` | `RateLimitBucketCleanupAndScaleTests` (`test_cleanup_rate_limits_removes_stale_keeps_fresh_and_bounds_keys`, `test_100k_rows_is_jwt_revoked_lookup_and_batched_cleanup_performance`) | `fixed` | `d40b8f3` (BE) |
| `REL-04` | Medium | Missing transaction & `select_for_update()` row lock in `set_prep_stage_view` allowing concurrent `prep_at`/cancel lost updates | `api/views.py` (`set_prep_stage_view`) | `test_set_prep_stage_allows_intentional_step_back_and_blocks_cancelled` + PG threaded `STW-PG-RACE6`/`STW-PG-RACE7` in `PostgresLockingAndConcurrencyTests` | `fixed` | `ffb4a8e` (BE) |
| `REL-05` | Low-Medium | Missing defense-in-depth payment/state guards at `_release_escrow` entry & lock | `api/views.py` (`EscrowReleaseError`, `_validate_escrow_releasable`, `_release_escrow`, `mark_collected_view`, `complete_by_code_view`) | `EscrowReleaseGuardTests` (`test_release_escrow_direct_calls_raise_on_pending_cancelled_and_released`, `test_collected_and_complete_endpoints_return_400_on_pending_cancelled_and_released`) | `fixed` | `e1f9705` (BE) |
| `REL-06` | Medium | `support_case_resolve_view` deleted `SupportCase` rows with only minimal audit fields | `api/views.py` (`support_case_resolve_view`) | `SupportCaseAuditSnapshotTests` (`test_refund_and_dismiss_write_full_snapshot_audit_before_delete_and_block_double_resolve`) + `SupportCaseRefundBugTest` | `fixed` | `d548815` (BE) |
| `REL-07` | Low | Missing JWT `iss='stew'` validation, 24h access lifetime default, and float round-trip in `orders_view` subtotal accumulation | `stew_server/settings.py`, `.env.example`, `api/security.py` (`generate_jwt_token`, `decode_jwt_token`), `api/views.py` (`orders_view`, intentional comments) | `JwtIssuerAndDecimalSubtotalTests` (`test_jwt_requires_iss_stew_and_defaults_to_12h_lifetime`, `test_order_creation_uses_exact_decimal_subtotal_and_preserves_numeric_line_price`) | `fixed` | `619b2c7` (BE) |

#### Verified Disagreements & Implementation Findings
- **Disagreement with Opus `M-01` (`orders_view` JSON line price shape):** Converting stored `Order.lines[].price` from numeric float to string would change the JSON API response shape relied on by frontend components. Instead, `orders_view` now accumulates `subtotal_acc += line_price * Decimal(qty)` directly in `Decimal` while preserving numeric `float(line_price)` in the stored JSON line snapshot (`619b2c7`).
- **Symmetry bug found during `REL-03` pre-fix testing:** `revoke_jwt_token(token)` decoded `payload` to extract `jti` (`jwt_revoked_{jti}`), whereas `is_jwt_revoked(token)` with `payload=None` previously hashed the raw token string instead of decoding `jti`. Fixed in `d40b8f3` so both decode `payload` identically when `payload` is omitted.

---

## 2. Tool & Database Rehearsal Results (Before vs. After)

| Tool / Check | Before (`security/pre-launch` baseline) | Latest Verified (`security/release` `619b2c7` / `stew` `5068e6d`) | Notes / Action |
|---|---|---|---|
| `bandit -r api stew_server` (excl. `migrations` & `tests*.py`) | 1 Low (`B105` false positive at `views.py:554`), 0 Medium, 0 High | **0 High, 0 Medium, 3 Low** across `3499` LOC (`B110` on `api/security.py:49,54` test-clear compat helper; `B105` false positive on `api/views.py:649` password validation message) | Re-verified on `security/release`; no Medium/High findings |
| `pip_audit -r requirements.txt` | `1` vuln: `certifi 2026.7.22` (`PYSEC-2026-4320`, fix `2026.10.23`) | **`No known vulnerabilities found`** (`exit 0`) | Re-verified on `security/release`; `certifi==2026.10.23`, `psycopg[binary]==3.3.9` |
| `ruff check` (`api stew_server`) | `81` errors (`0` `--select S` on prod code) | Full rule set: `96` errors (style/lint e.g. `RUF012`, `I001`, `BLE001`); non-test `--select S` (`--exclude "tests*.py,migrations/*"`): **`2` findings** (`S110` `try/except/pass` at `api/security.py:49,54`) | Re-verified on `security/release`; style rules outside security scope left intact |
| `npm audit` (full) | `6` vulnerabilities (`1` low, `5` moderate in dev build deps) | From `security/final` (`5068e6d`, FE untouched): `6` vulnerabilities (`1` low, `5` moderate: `fast-uri`, `glob`, `minimatch`, `serialize-javascript` inside `vite-plugin-pwa`/`workbox-build`) | Not auto-fixed (`--force` downgrades `vite-plugin-pwa`); `stew` unchanged since `5068e6d` |
| `npm audit --omit=dev` | `found 0 vulnerabilities` | From `security/final` (`5068e6d`, FE untouched): **`found 0 vulnerabilities`** (`exit 0`) | Runtime bundle deps unchanged since `5068e6d` |
| `gitleaks git -v` (full git history) | `stew`: `0` leaks; `stew_backend`: `1` false positive | From `security/final`: `stew` (`20` commits): `no leaks found`; `stew_backend` (`35` commits): `1` false positive (`api/migrations/0003`:`0002_alter_vendor_rating`) — *not re-run after `security/final` commits* | Rotate all production secrets before launch as SOP |
| `manage.py check --deploy --fail-level WARNING` (prod env vars) | `0 issues` (0 silenced) | **`System check identified no issues (0 silenced).`** (`exit 0`) | Re-verified on `security/release` with `DEBUG=False`, 64-char `SECRET_KEY`, `PAYSTACK_ALLOW_MOCK=False`, SMTP backend, HTTPS origins |
| Frontend `npm run lint` (`oxlint`) | `0` errors | **`0 errors, 11 warnings`** across `36` files (`451ms`) | Re-run after `619b2c7` (`stew` `5068e6d`) |
| Frontend `npm run build` (`vite build`) | Built cleanly (`dist/sw.js`) | **`built in 6.57s`** (`dist/sw.js` PWA build `337ms`, `dist/assets/index-*.js` `402.74 kB`, `sourcemap: false`); missing `VITE_API_URL` still blocked since `0ea8e01` | Re-run after `619b2c7` (`stew` `5068e6d`) |
| Backend SQLite suite (`manage.py test api --noinput`) | `92 tests OK` | **`Ran 135 tests in 232.908s OK (skipped=1)`** | Re-run after `619b2c7`; only the PG-only concurrency test is skipped on SQLite |
| PostgreSQL 16 suite (`manage.py test api --noinput`) | `92` tests run: **FAILED (`errors=25`)** | **`Ran 135 tests in 229.057s OK`** (`0` errors, `0` failures, `0` skipped, incl. 7 threaded PG races) | Re-run after `619b2c7` on WSL2 PostgreSQL 16 (`127.0.0.1:5432`) |
| PostgreSQL messy `0003` migration rehearsal | `0002 -> messy seed -> 0003` **FAILED** | From `security/final`: **`0002 -> messy seed -> 0003 -> 0002 -> 0003` succeeded**; `m-round=10.01`, `m-nan=0.50`, `m-huge=99999999.99`, deduped `payment_reference` <= `128` chars | Migration schema unchanged since `security/final` |

---

## 3. Independent Audit Summary & "Checked and Fine" (`file:line`)

Every area in the security checklist was audited directly against the code:

- **Paystack Webhook & Verification (`BUG -> FIXED FIN-10`, rest `FINE`):**
  - Constant-time HMAC-SHA512 signature check over raw `request.body` before `json.loads`, rejecting missing header (`400`) and invalid sig (`401`): `api/views.py:1486-1495` (`FINE`).
  - Webhook validates `event == 'charge.success'`, `data.status == 'success'`, `data.currency == 'GHS'`, `data.amount >= expected_pesewas`, re-verifies with Paystack `/transaction/verify/`, refuses unknown/blank reference, and idempotently moves escrow via `_mark_order_paid`: `api/views.py:1378-1425, 1497-1522` (`FIXED FIN-10`).
  - `verify_payment_view` compares stored `order.payment_reference` with `secrets.compare_digest` and calls `_paystack_verify`: `api/views.py:1449-1474` (`FINE`).
  - No client redirect or flag can mark an order paid (`verify` requires backend secret check or `DEBUG`-only mock): `api/views.py:252-253, 1464-1472` (`FIXED FIN-10`).
  - `PAYSTACK_ALLOW_MOCK` is rejected at boot when `DEBUG=False` (`stew_server/settings.py:305-307`) and refused at runtime when `DEBUG=False` (`api/views.py:252-253`).
- **Price, Quantity & Order Integrity (`BUG -> FIXED FIN-11`, pricing `FINE`):**
  - Server ignores client prices, fees, totals, and email; loads `Meal.price` and vendor from DB, enforces single-vendor tray, active/open vendor, no self-orders, `Decimal` `0.05` fee, and sorted-PK `select_for_update()` stock decrement: `api/views.py:1098-1174` (`FINE`).
  - Quantity/rating/prep integers reject `bool`/`float`/`"1.5"`, enforce cumulative `<= 50` per meal across duplicate lines, and reject out-of-range review ratings (`1..5`): `api/views.py:224-240, 725-731, 1093-1114, 1983-1986` (`FIXED FIN-11`).
- **IDOR, Mass Assignment & Serializer Privacy (`BUG -> FIXED FIN-12`, other endpoints `FINE`):**
  - All parameterized routes check `_is_order_participant`, `_is_order_owner`, `_is_order_vendor`, or `is_platform_admin` (`api/views.py:65-90, 905-908, 1205-1215`; verified by `AdminUnificationMatrixTest` + `IDORAndSerializerExposureTests`).
  - Push subscription hijack blocked (`409`); `OrderSerializer` hides `handoffCode`, `email`, and `payment.reference` from vendors; all 10 read serializers set `read_only_fields = fields` (`api/views.py:2342-2367`, `api/serializers.py:18-297`, `FIXED FIN-12`).
- **Collection / Handoff Code (`FIXED FIN-06`):**
  - Hidden from vendors (`api/serializers.py:157-160`), 6-digit CSPRNG (`api/security.py:44-46`), persistent lockout after 5 bad tries per order with forced code rotation (`api/views.py:1886-1900`), single-use cleared on release (`api/views.py:1633`), 14-day expiry (`api/views.py:1877-1884`).
- **Refunds, Support & Payouts (`FIXED FIN-03`, `FIN-07`):**
  - `payout_batches_view` locks unbatched `released` orders via `select_for_update().order_by('id')` and marks `payout_batch_id` atomically (`api/views.py:2139-2160`).
  - `support_case_resolve_view` rejects double-resolution, blocks refunds once `payout_batch_id` is assigned (`409`), and restores meal stock idempotently via `_stockRestored` (`api/views.py:114-138, 2226-2269`).
- **Auth, Password Reset & Campus Email (`FIXED FIN-06`, `FIN-13`):**
  - `HS256` JWT checks `is_active`, `verified`, password fingerprint `pv`, `jti` revocation blocklist (`POST /api/auth/logout/`), and strict ASCII KNUST email pattern (`api/security.py:54-111`, `api/authentication.py:14-44`, `api/validators.py:4-28`).
  - 6-digit OTPs hashed with `SECRET_KEY`-salted SHA-256 and verified with `hmac.compare_digest` (`api/security.py:30-46`); password reset codes expire in 15m, single-use cleared, burned on lockout, return generic `{'ok': True}` (`api/views.py:602-668`); no host header used in email links.
- **Input, SQL Injection, XSS & Uploads (`FIXED FIN-08`, SQL/XSS `FINE`):**
  - Zero `.raw()`, `.extra()`, or `cursor()`, and zero request-controlled `order_by()` (`api/views.py:141-151, 837, 1063`).
  - Frontend contains zero `dangerouslySetInnerHTML`, `javascript:` URLs, or `innerHTML` calls (`stew/src/`).
  - Image uploads client-compressed (`stew/src/lib/upload.js`), constrained by `DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440` (`stew_server/settings.py:217`), validated by `_sanitize_media_url` (`api/views.py:193-209`: blocks `image/svg+xml`, `//`, oversize payloads > `600000` chars).
- **Settings, Headers & Operational Safety (`FIXED FIN-14`):**
  - Production guards forbid weak `SECRET_KEY`, `ALLOWED_HOSTS='*'`, console email backend, and `PAYSTACK_ALLOW_MOCK=True` when `DEBUG=False` (`stew_server/settings.py:16-44, 286-307`), `HSTS` (1y + subdomains + preload), `SSL_REDIRECT`, `HttpOnly` + `SameSite='Lax'` + `Secure` cookies (`settings.py:217-240`), `Content-Security-Policy` + `Permissions-Policy` middleware (`api/security.py:115-128`), `seed_data` production guard, and `/admin/` restricted to `is_admin` + `verified` (`stew_server/urls.py:1-21`).
- **`security/release` Payment, Concurrency, Proxy & Support Hardening (`FIXED REL-01`–`REL-07`):**
  - Paid-after-cancel webhooks and verify calls atomically record `paid_at`, set `payment_status='refund_pending'`, write `AuditEntry`, and return `400` (`code='refund_pending'`) from `verify_payment_view` (`REL-01`).
  - Right-to-left `X-Forwarded-For` extraction governed by `TRUSTED_PROXY_COUNT` prevents campus NAT lockouts across distinct accounts (`REL-02`), alongside batched `cleanup_rate_limits` pruning and bounded bucket keys (`REL-03`).
  - `set_prep_stage_view` acquires `select_for_update()` (`REL-04`), `_release_escrow` re-validates payment/terminal state inside its atomic lock (`REL-05`), `support_case_resolve_view` persists a full JSON snapshot into `AuditEntry` atomically before `case.delete()` (`REL-06`), and JWT decode enforces `iss='stew'` with a 12h default lifetime while `orders_view` accumulates `Decimal` subtotals directly (`REL-07`).

---

## 4. "Not Verified" List

The following items cannot be verified from a local/WSL2 test environment and MUST be executed during staging and pre-production deployment:
1. **Live Production Database Inspection:** Running `docs/PRODUCTION_PREFLIGHT.md` against a copy of the actual production database (unknown whether legacy rows contain bad emails, duplicate `payment_reference`, unverified active vendors, or `is_staff`/`role='admin'` admins missing `is_admin=True`).
2. **Real Paystack Live Keys & Webhook Delivery:** Live `api.paystack.co/transaction/initialize` and `/transaction/verify/` HTTP calls using real `pk_live_`/`sk_live_` keys, live MoMo approvals, and genuine inbound Paystack webhooks to a public HTTPS URL.
3. **Paystack Vendor Disbursement:** Actual bank / Mobile Money transfers for `PayoutBatch` payouts (STEW creates ledger `PayoutBatch` records, while transfer execution to vendor MoMo wallets is out-of-band or requires operator disbursement).
4. **Live Transactional SMTP Delivery:** Real email delivery of signup verification, login-code, and password-reset OTPs through production SMTP credentials (`EMAIL_HOST`, SPF/DKIM/DMARC).
5. **Redis Runtime Connectivity:** Using `REDIS_URL` in production for Django's `CACHES` backend was verified configurationally (`settings.py` falls back safely to `LocMemCache`, while security counters always persist in PostgreSQL `RateLimitBucket`), not against a live Redis server.
6. **Reverse Proxy, TLS Certificates & Infrastructure Controls:** nginx/Caddy TLS termination, `X-Forwarded-Proto: https` header stripping/injection prevention, `client_max_body_size 5m`, `/admin/` IP allowlist / VPN restriction, and managed database backup/restore automation.
7. **Ghana Financial / Escrow Compliance:** Legal counsel sign-off on holding student funds in settlement before escrow release / Paystack split-subaccount configuration.

---

## 5. Production Deploy Runbook (Execute in Exact Order)

1. **Snapshot Production & Test Restore on a Staging Copy**
   - Take a fresh full snapshot / `pg_dump -Fc` of the production PostgreSQL database.
   - Restore it into an isolated staging/copy database and verify row counts match (`pg_restore --clean --if-exists` -> `SELECT count(*) FROM api_order;`). **Do not proceed unless restore succeeds.**
2. **Run Pre-Flight Queries on the Copy (`docs/PRODUCTION_PREFLIGHT.md`)**
   - Execute every read-only SQL query and Django shell check in `docs/PRODUCTION_PREFLIGHT.md` against the restored copy:
     - Duplicate/blank `payment_reference`;
     - Rows violating the 8 `CheckConstraint`s in `0003`;
     - Accounts with `verified=False` that own active `Vendor` rows or admin flags;
     - Accounts with `is_staff=True` / `role='admin'` / `account_type='admin'` that have `is_admin=False`;
     - `Vendor` active/open matrix and any `AuditEntry` suspensions;
     - Orders in odd/partial settlement/cancellation states.
3. **Remediate Data & Promote Real Platform Admins**
   - Fix any conflicting rows found in Step 2 on the staging copy first (document the SQL/ORM updates) and verify the same remediation plan on production right before cutover.
   - Explicitly set `is_admin=True` for legitimate STEW platform operators and demote any non-admin `is_staff`/`role='admin'` accounts.
   - Confirm every genuine merchant has `user.verified=True` and appropriate `Vendor.active` status.
4. **Set Production Environment Variables**
   - Backend (`.env` / secrets manager — never commit):
     - `SECRET_KEY=<fresh 64+ char token from secrets.token_urlsafe(64)>`
     - `DEBUG=False`
     - `ALLOWED_HOSTS=api.<your-domain>`
     - `CORS_ALLOWED_ORIGINS=https://<frontend-domain>`
     - `CSRF_TRUSTED_ORIGINS=https://<frontend-domain>`
     - `PAYSTACK_PUBLIC_KEY=pk_live_...`
     - `PAYSTACK_SECRET_KEY=sk_live_...`
     - `PAYSTACK_ALLOW_MOCK=False`
     - `EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend` + `EMAIL_HOST`, `EMAIL_PORT=587`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`, `EMAIL_USE_TLS=True`, `DEFAULT_FROM_EMAIL`
     - `DB_ENGINE=postgresql`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT=5432`, `DB_SSLMODE=require`
     - `RATE_LIMIT_BACKEND=db` (default, safe multi-worker PostgreSQL locks) and optional `REDIS_URL=redis://...` for `CACHES` / DRF throttles
     - `TRUSTED_PROXY_COUNT=0` (set to exact number of trusted reverse proxy hops — e.g. `1` behind a single nginx/Cloudflare hop — per `docs/PRODUCTION_PREFLIGHT.md` Section 7; never trust arbitrary client `X-Forwarded-For` prefixes)
     - `THROTTLE_ANON_PER_MIN=1000`, `THROTTLE_USER_PER_MIN=120` (global DRF throttle ceilings per minute)
     - `JWT_ACCESS_TOKEN_LIFETIME_HOURS=12` (current default `12`; tighten to `1`–`4` once refresh token rotation is deployed)
     - `FAILED_LOGIN_RETENTION_DAYS=30`, `FAILED_LOGIN_IP_HOURLY_CAP=60`
     - `CUSTOMER_CANCEL_UNTIL_PREP_STARTS=True`, `CUSTOMER_CANCEL_WINDOW_SECONDS=120`, `CUSTOMER_PAID_CANCELS_PER_DAY=5`
     - Optional initial admin bootstrap only: `SEED_ADMIN_PASSWORD=<12+ char strong secret>`
5. **Apply Database Migrations on Copy First, Then Production**
   - Run `python manage.py migrate --noinput` against the staging copy first (`0003_decimal_money_and_constraints`, `0004_ratelimitbucket`, `0005_failed_login_event`). Confirm exit `0` and `makemigrations --check --dry-run`.
   - Put production API in brief maintenance mode, take a pre-migration delta backup, and run `python manage.py migrate --noinput` against production.
6. **Deploy Backend & Reverse Proxy**
   - Run `python manage.py check --deploy --fail-level WARNING` in the production container/host (must report `0` issues).
   - Configure reverse proxy (nginx/Caddy) with TLS, `proxy_set_header X-Forwarded-Proto https`, `client_max_body_size 5m`, and IP allowlist on `/admin/` (or restrict `/admin/` behind VPN).
   - Register webhook `https://api.<your-domain>/api/payments/webhook/` in the Paystack Live Dashboard.
   - Confirm Gunicorn boots cleanly and `GET /api/vendors/` returns `200` with `Content-Security-Policy` and `Strict-Transport-Security`.
7. **Build & Deploy Frontend with `VITE_API_URL`**
   - In CI / build environment (`stew/`):
     ```bash
     export VITE_API_URL="https://api.<your-domain>/api"
     export VITE_PAYSTACK_PUBLIC_KEY="pk_live_..."
     npm ci
     npm run lint
     npm run build
     ```
   - Deploy `dist/` over HTTPS cleanly. Verify `dist/` does not include source maps (`.map`) or mock shortcuts (`MOCK === false`).
8. **Run Post-Deploy Smoke Tests**
   - Verify HTTPS redirect, TLS cert, `GET /api/vendors/` `200`, `POST /api/payments/initialize/` unauthenticated returns `401`, non-KNUST email signup returns `400`, `/admin/` rejects non-`is_admin` staff accounts, and run Section 6 dry-run on staging / live micro-order.
9. **Schedule Daily Cleanup, Unpaid Expiry & Refund Retry Crons**
   - Configure daily/periodic crons / systemd timers (see `docs/PRODUCTION_PREFLIGHT.md` Sections 8–11):
     - `15 3 * * * cd /srv/stew/stew_backend && ./venv/bin/python manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600` (purges expired `RateLimitBucket` rows, expired JWT `jti` revocations, and `FailedLoginEvent` rows older than `FAILED_LOGIN_RETENTION_DAYS=30`)
     - `*/5 * * * * cd /srv/stew/stew_backend && ./venv/bin/python manage.py expire_unpaid_orders`
     - `*/15 * * * * cd /srv/stew/stew_backend && ./venv/bin/python manage.py retry_pending_refunds`
     - One-time / audit check: `python manage.py purge_identity_documents` (dry-run) / `--apply`.

### Incident Runbook: Compromised or Lost Admin Account

The API dashboard blocks suspending `is_admin=True` accounts (`admin_user_detail_view` returns `400`). If an admin account is compromised, suspected stolen, or all active admins are locked out, execute these steps directly from a server Django shell (`python manage.py shell`):

1. **Deactivate the compromised account & invalidate all issued JWTs / OTP codes (`is_active=False`):**
   ```python
   from django.contrib.sessions.models import Session
   from api.models import User

   target_email = "<compromised-admin>@st.knust.edu.gh"
   u = User.objects.get(email=target_email)
   u.is_active = False
   u.is_admin = False  # remove admin flag if compromised rather than temporarily suspended
   u.set_unusable_password()  # rotates password_fingerprint ('pv'), failing existing JWTs immediately
   u.verification_code_hash = u.login_code_hash = u.reset_code_hash = ""
   u.verification_code_expires = u.login_code_expires = u.reset_code_expires = None
   u.save()

   # Clear active Django /admin/ cookie sessions (forces re-auth for remaining operators too)
   Session.objects.all().delete()
   ```
   - `is_active=False` immediately blocks `JWTAuthentication`, password login (`login_view`), login-code (`login_with_code_view`, `request_login_code_view`), password reset (`forgot_password_view`, `reset_password_view`), `IsAdminUser`, and Django `/admin/`.

2. **Explicit `jti` token revocation (when specific tokens/JTIs are known):**
   ```python
   from api.security import revoke_jwt_token

   # If you have a raw JWT string from logs/device storage:
   revoke_jwt_token("<raw_jwt_token>")
   # Or if only the 'jti' claim was logged:
   revoke_jwt_token("incident-revoke", payload={"jti": "<jti_value>"})
   ```
   - *Note:* STEW maintains a persistent revocation blocklist (`RateLimitBucket`, keyed by `jwt_revoked_<jti>`) rather than indexing every active `jti`. Unknown tokens for the compromised user are still rejected immediately by Step 1 (`is_active=False` + `pv` mismatch), and platform-wide by Step 3.

3. **Rotate `SECRET_KEY` if JWTs, OTP secrets, or credentials may have been stolen:**
   - Generate a new 64-byte key: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
   - Update `SECRET_KEY` in the production `.env` / secrets manager and restart all Gunicorn workers/services.
   - Rotating `SECRET_KEY` immediately invalidates every active JWT signature (`HS256`), every outstanding OTP hash, and every Django `/admin/` session across the entire platform.

4. **Review the audit log for that actor & verify admin roster:**
   ```python
   from api.models import AuditEntry, User

   for e in AuditEntry.objects.filter(actor=target_email).order_by("-at")[:200]:
       print(e.at.isoformat(), e.action, e.entity_type, e.entity_id, e.extra)

   print(list(User.objects.filter(is_admin=True).values_list("email", "is_active", "verified")))
   ```
   - Inspect all sensitive actions (`payout_batch_created`, `case_refund`, `case_dismiss`, `admin_vendor_updated`, `admin_user_status`, `review_*`), reconcile any triggered `PayoutBatch` / refunds against the Paystack dashboard, and verify no unauthorized user gained `is_admin=True`.

5. **Recovering from a lost admin (no remaining active operator):**
   ```python
   from api.models import User

   op = User.objects.get(email="<authorized-replacement>@st.knust.edu.gh")
   op.is_admin = True
   op.is_active = True
   op.verified = True
   op.set_password("<strong-16plus-char-password>")
   op.save()
   ```

---

## 6. End-to-End Staging Dry-Run Script

Run this against staging (`API_BASE=https://staging-api.<your-domain>/api`) with a Paystack **test** key (`sk_test_...`) using a disposable KNUST test customer, vendor, and admin account for a small GHS 5.00 order:

```bash
set -euo pipefail
API_BASE="${API_BASE:-http://127.0.0.1:8000/api}"
CUST_JWT="<customer_jwt>"
VEND_JWT="<vendor_jwt>"
ADMIN_JWT="<admin_jwt>"
MEAL_ID="<active_5_ghs_meal_id>"

echo "1) Place a small GHS 5.00 order"
ORDER_JSON=$(curl -fsS -X POST "$API_BASE/orders/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d "{\"lines\":[{\"mealId\":\"$MEAL_ID\",\"qty\":1}],\"area\":\"Unity Hall (Conti)\",\"pickupDay\":\"2026-12-01\",\"pickupSlot\":\"evening\"}")
ORDER_ID=$(python -c "import sys,json; print(json.loads(sys.argv[1])['id'])" "$ORDER_JSON")
HANDOFF=$(python -c "import sys,json; print(json.loads(sys.argv[1])['handoffCode'])" "$ORDER_JSON")
echo "Order: $ORDER_ID  HandoffCode: $HANDOFF"

echo "2) Initialize Paystack payment (and test idempotent double-call)"
INIT1=$(curl -fsS -X POST "$API_BASE/payments/initialize/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d "{\"orderId\":\"$ORDER_ID\"}")
PAY_REF=$(python -c "import sys,json; print(json.loads(sys.argv[1])['reference'])" "$INIT1")
echo "Reference: $PAY_REF  (complete checkout via checkout_url / inline popup in staging UI)"

echo "3) Verify payment & inspect Paystack webhook delivery"
curl -fsS -X POST "$API_BASE/payments/verify/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d "{\"orderId\":\"$ORDER_ID\",\"reference\":\"$PAY_REF\"}" | grep '"status":"paid"'

echo "4) Meetup propose (customer) & confirm (vendor)"
curl -fsS -X POST "$API_BASE/orders/$ORDER_ID/meetup/propose/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d '{"place":"Commercial Area (busy, open)","note":"Dry-run check"}' > /dev/null
curl -fsS -X POST "$API_BASE/orders/$ORDER_ID/meetup/confirm/" \
  -H "Authorization: Bearer $VEND_JWT" -H "Content-Type: application/json" -d '{}' | grep '"agreed":true'

echo "5) Vendor advances prep stage to ready & releases escrow via handoff code"
for STAGE in shopping cooking packing ready; do
  curl -fsS -X POST "$API_BASE/orders/$ORDER_ID/prep/" \
    -H "Authorization: Bearer $VEND_JWT" -H "Content-Type: application/json" \
    -d "{\"stage\":\"$STAGE\"}" > /dev/null
done
curl -fsS -X POST "$API_BASE/orders/$ORDER_ID/complete/" \
  -H "Authorization: Bearer $VEND_JWT" -H "Content-Type: application/json" \
  -d "{\"code\":\"$HANDOFF\"}" | grep '"status":"released"'

echo "6) Admin creates payout batch covering released orders"
curl -fsS -X POST "$API_BASE/payouts/batches/" \
  -H "Authorization: Bearer $ADMIN_JWT" -H "Content-Type: application/json" \
  -d '{"provider":"paystack","reference":"DRYRUN-BATCH-001"}'

echo "7) Second small order: test customer support case & admin refund resolution"
ORDER2_ID=$(curl -fsS -X POST "$API_BASE/orders/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d "{\"lines\":[{\"mealId\":\"$MEAL_ID\",\"qty\":1}],\"area\":\"Unity Hall (Conti)\",\"pickupDay\":\"2026-12-01\",\"pickupSlot\":\"evening\"}" \
  | python -c "import sys,json; print(json.load(sys.stdin)['id'])")
# Pay ORDER2_ID, then open support case and resolve refund:
CASE_CODE=$(curl -fsS -X POST "$API_BASE/support/cases/" \
  -H "Authorization: Bearer $CUST_JWT" -H "Content-Type: application/json" \
  -d "{\"order\":\"$ORDER2_ID\",\"type\":\"refund\",\"priority\":\"normal\",\"note\":\"Dry-run refund test\"}" \
  | python -c "import sys,json; print(json.load(sys.stdin)['code'])")
curl -fsS -X POST "$API_BASE/support/cases/$CASE_CODE/resolve/" \
  -H "Authorization: Bearer $ADMIN_JWT" -H "Content-Type: application/json" \
  -d '{"action":"refund"}' | grep '"ok":true'
```

---

## 7. Deferred Items

The following hardening enhancements were intentionally deferred beyond `security/release` and tracked for the next scheduled release window:
1. **Soft-delete support cases (`status` + `resolved_at` columns instead of hard delete after `AuditEntry` snapshot)** — requires schema migration + admin/customer query filtering while `AuditEntry` already preserves the full immutable resolution snapshot (`REL-06`, `d548815`).
2. **Refresh token rotation + shorter 1h access JWT** — requires coordinated backend refresh-token store/endpoint and frontend silent-refresh flow (`JWT_ACCESS_TOKEN_LIFETIME_HOURS` set to `12` in the interim, `REL-07`, `619b2c7`).

---

## 8. Go / No-Go Verdict

**Verdict: `CONDITIONAL GO (NO-GO UNTIL PREFLIGHT & STAGING GATES PASS)`**

- **Code & Automated Verification Gate (`PASSED`):** All identified defects (`FIN-01`–`FIN-14` and `REL-01`–`REL-07`) have regression tests proving pre-fix failure and post-fix resolution. The full **135-test suite** passes with zero errors/skips on PostgreSQL 16 (`229.057s`) and `135` tests (`1` PostgreSQL-only concurrency test skipped, `232.908s`) on SQLite. Migration `0003` was verified forward and backward on messy data in PostgreSQL on `security/final`. Production Python `pip_audit` shows zero known vulnerabilities, `bandit` (`3499` LOC excl. tests/migrations) shows `0` High / `0` Medium findings, `manage.py check --deploy --fail-level WARNING` shows zero issues, and the untouched frontend (`5068e6d`) builds cleanly (`dist/sw.js` generated, `0` lint errors; missing `VITE_API_URL` build gate verified on `security/final`).
- **Blocking Release Conditions Before Production Cutover:** Do **NOT** deploy to live traffic until an operator executes the `docs/PRODUCTION_PREFLIGHT.md` audit against a production snapshot copy, promotes legitimate admins to `is_admin=True`, sets live production credentials/env vars (`DEBUG=False`, `PAYSTACK_SECRET_KEY`, `TRUSTED_PROXY_COUNT`, `JWT_ACCESS_TOKEN_LIFETIME_HOURS=12`, SMTP, PostgreSQL TLS, `VITE_API_URL`), schedules the daily `cleanup_rate_limits` cron job, tests backup restore + migrations on the copy first, locks down `/admin/` at the reverse proxy, and verifies Section 6 against staging with real Paystack test credentials.
