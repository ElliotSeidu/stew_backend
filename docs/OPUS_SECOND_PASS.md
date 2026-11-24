# OPUS Second-Pass Security Review — STEW

**Date:** 2026-11-18
**Reviewer:** Claude (independent, read-only)
**Branch:** `security/release` (backend), `security/final` (frontend)
**Scope:** Everything NOT covered by the first Opus payment review.
**Status:** COMPLETE

## Verdict

**CONDITIONAL GO** — no show-stoppers found, but 5 findings should be addressed before launch.
The Gemini fixes are substantive and well-implemented. The settings hardening, rate limiting,
input validation, and IDOR protections are all verified as working correctly. The codebase
is significantly above average for a student project.

---

## Findings (sorted by severity)

| # | Severity | Area | File:Line | Title | Confidence |
|---|----------|------|-----------|-------|------------|
| S2-01 | Medium | Models | models.py:89 | Vendor.rating uses FloatField for aggregated money-adjacent value | CONFIRMED |
| S2-02 | Medium | Frontend | api.js:7 | Mock mode can activate in dev builds with missing VITE_API_URL | CONFIRMED |
| S2-03 | Low | Admin | views.py:2433 | Admin can suspend other admin's vendors but not the admin user | CONFIRMED |
| S2-04 | Low | Settings | settings.py:231 | SECURE_BROWSER_XSS_FILTER is deprecated/no-op in modern browsers | CONFIRMED |
| S2-05 | Low | Rate Limit | security.py:41-55 | _RateLimitCacheStore grows unbounded in memory between cleanup | CONFIRMED |
| S2-06 | Info | Frontend | analytics.js:13 | console.debug in mock mode leaks analytics payloads | CONFIRMED |
| S2-07 | Info | Models | models.py:84-100 | Vendor model missing db_index on user FK and active field | SUSPECTED |

---

## Detailed Findings

### S2-01: Vendor.rating uses FloatField (Medium) — CONFIRMED

**File:** `api/models.py:89`
```python
rating = models.FloatField(default=0.0)
```
**Impact:** FloatField introduces IEEE 754 rounding artifacts when storing averaged ratings
computed from integer stars. While not money, it affects displayed ratings (e.g., 4.15000001
instead of 4.2). The `_recompute_vendor_rating` function at views.py:2033 does
`round(agg['avg'], 1)` which mitigates display, but the stored value may still drift.
**Fix:** Change to `DecimalField(max_digits=3, decimal_places=1, default=Decimal('0.0'))`.
**Confidence:** CONFIRMED — verified field type in models.py:89 and aggregation in views.py:2033.

### S2-02: Mock mode can activate in non-production dev builds (Medium) — CONFIRMED

**File:** `stew/src/lib/api.js:7`
```javascript
export const MOCK = !import.meta.env.PROD && (import.meta.env.VITE_USE_MOCK === 'true' || !BASE)
```
**Impact:** If a developer runs `npm run dev` without setting `VITE_API_URL`, the entire API
layer silently falls back to localStorage-based mock data. This isn't a production risk (the
build plugin at vite.config.js:6-22 blocks production builds without `VITE_API_URL`), but it
means dev testing may not hit the real backend, masking bugs.
**Fix:** Add a prominent console.warn when MOCK activates, or require explicit `VITE_USE_MOCK=true`.
**Confidence:** CONFIRMED — verified vite.config.js enforceApiUrlPlugin blocks prod builds.

### S2-03: Admin cannot suspend another admin user (Low) — CONFIRMED

**File:** `api/views.py:2432-2434`
```python
if is_platform_admin(target):
    return Response({'message': 'Admin accounts cannot be suspended from the dashboard.'}, ...)
```
**Impact:** This is intentional defense (prevents admin lock-out), but means a compromised
admin account cannot be suspended by another admin through the dashboard. Would require DB access.
Admin vendors CAN be deactivated though (admin_vendor_detail_view has no such guard).
**Fix:** Consider allowing an admin to suspend another admin but not themselves. Low priority
since there's likely only one admin for MVP.
**Confidence:** CONFIRMED — verified at views.py:2433.

### S2-04: SECURE_BROWSER_XSS_FILTER deprecated (Low) — CONFIRMED

**File:** `stew_server/settings.py:231`
```python
SECURE_BROWSER_XSS_FILTER = True
```
**Impact:** The `X-XSS-Protection` header this sets is deprecated and disabled in modern
browsers (Chrome removed it in 2019). No harm but gives false confidence. The real XSS
protection is the CSP header (correctly set in security.py:181).
**Fix:** Remove the setting or set to False. Add a comment that CSP is the real protection.
**Confidence:** CONFIRMED.

### S2-05: _RateLimitCacheStore grows unbounded in memory (Low) — CONFIRMED

**File:** `api/security.py:41-55`
```python
class _RateLimitCacheStore(dict):
    """Compatibility store so _RATE_LIMIT_CACHE.clear() resets DB buckets in tests."""
```
**Impact:** `_RATE_LIMIT_CACHE` (in-memory dict) is appended to by `check_rate_limit` at
lines 206, 215, 223 but never pruned during normal operation. Only `.clear()` is implemented
(for tests). Over weeks, this dict grows to hold thousands of keys. Not a security vuln but
a memory leak. The DB-backed `RateLimitBucket` table also grows without cleanup.
**Fix:** Add a periodic cleanup (e.g., management command or cron) to delete
RateLimitBucket rows older than their window. The in-memory dict is optional and can be
dropped since rate limiting is DB-backed.
**Confidence:** CONFIRMED — no cleanup path found outside `.clear()`.

### S2-06: console.debug in mock mode (Info) — CONFIRMED

**File:** `stew/src/lib/analytics.js:13`
```javascript
if (MOCK) { console.debug('[analytics]', payload); return }
```
**Impact:** Logs analytics payloads to browser console in dev. Harmless in production since
MOCK is false when VITE_API_URL is set, but could confuse developers.
**Confidence:** CONFIRMED.

### S2-07: Vendor model missing indexes (Info) — SUSPECTED

**File:** `api/models.py:84-100`
```python
class Vendor(models.Model):
    user = models.ForeignKey(User, ...)  # auto-indexed by FK
    active = models.BooleanField(default=True)  # no explicit index
```
**Impact:** `Vendor.objects.filter(active=True)` is used in multiple views (vendors_list_view,
meals_list_view, payout_batches_view). With a small vendor count (university campus), this
is fine. At scale, an index on `active` would help. The FK to User is auto-indexed by Django.
**Fix:** Add `db_index=True` to `active` field if vendor count grows past ~1000.
**Confidence:** SUSPECTED — small dataset makes this theoretical.

---

## Checked and Fine

### Settings (settings.py)
- ✅ **SECRET_KEY**: 32-char minimum enforced, weak-key guard blocks production startup (line 20-23)
- ✅ **DEBUG**: Defaults to False, requires explicit opt-in (line 14)
- ✅ **ALLOWED_HOSTS**: Rejects `*` in production (line 40-44)
- ✅ **CORS**: CORS_ALLOWED_ORIGINS uses explicit list, no wildcard. CORS_ALLOW_CREDENTIALS=True paired with explicit origins (line 191-201) — safe per spec
- ✅ **CSRF**: CSRF_COOKIE_HTTPONLY=True, CSRF_COOKIE_SAMESITE='Lax', CSRF_COOKIE_SECURE=True in prod (lines 226-246)
- ✅ **Session cookies**: SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=True in prod
- ✅ **HSTS**: 1 year, include_subdomains, preload all set in production (lines 242-244)
- ✅ **SSL redirect**: SECURE_SSL_REDIRECT=True in production (line 241)
- ✅ **CSP**: `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` on API responses (security.py:181)
- ✅ **DATABASE**: No hardcoded creds — all from env vars with sslmode=require default (lines 100-122)
- ✅ **EMAIL_BACKEND**: Console backend blocked in production (lines 294-298)
- ✅ **PAYSTACK_ALLOW_MOCK**: Blocked in production with RuntimeError (lines 314-315)
- ✅ **DATA_UPLOAD_MAX_MEMORY_SIZE**: 2.5 MB limit (line 224)
- ✅ **DRF throttling**: 300/min anon, 120/min user, NUM_PROXIES synced with TRUSTED_PROXY_COUNT (lines 180-184)

### Proxy / Rate Limiting
- ✅ **get_client_ip**: TRUSTED_PROXY_COUNT=0 defaults to REMOTE_ADDR only — no XFF spoofing possible (security.py:11-38)
- ✅ **XFF right-to-left**: When TRUSTED_PROXY_COUNT > 0, extracts Nth from right, validates as IP address
- ✅ **NAT lockout**: 300/min anon rate is generous enough for campus NAT; per-email limits prevent individual abuse
- ✅ **Rate limit keys**: _normalize_rate_limit_key hashes keys > 200 chars, prevents unbounded key creation (security.py:131-135)
- ✅ **JWT revocation**: is_jwt_revoked uses DB-backed RateLimitBucket, survives restart (security.py:156-167)

### Vendor Onboarding
- ✅ **vendor_apply_view**: Rate limited (5/5min), escapes all inputs, validates phone (views.py:959-1030)
- ✅ **Suspended vendor**: Cannot reactivate without admin (views.py:978-982, 1040-1044)
- ✅ **IsVendorUser**: Requires is_active=True, verified=True (authentication.py:67-82)
- ✅ **Inactive vendor gate**: _inactive_vendor_response blocks meals/orders for suspended vendors (views.py:92-101)
- ✅ **Email immutable**: me_view rejects email changes (views.py:701-704)
- ✅ **RegisterSerializer**: accountType restricted to ['customer', 'vendor', 'both'] — no 'admin' (serializers.py:51)
- ✅ **verify_email_view**: Brute-force protected, burns OTP on lockout, constant-time comparison (views.py:400-462)

### Admin Endpoints
- ✅ **IsAdminUser**: All admin views decorated with `@permission_classes([IsAdminUser])` — verified on moderation_queue_view, moderate_review_view, admin_compliance_view, admin_vendors_view, admin_vendor_detail_view, admin_users_view, admin_user_detail_view, admin_audit_view, payout_batches_view
- ✅ **record_audit**: Called on all admin mutations — vendor update (2411), user status (2439), payout batch (2247), case resolve (2371-2378), review moderation (2149)
- ✅ **AdminUserSerializer**: Exposes only id, name, email, role, accountType, isAdmin, active, verified, hall (serializers.py:308-311) — no password hashes, no codes
- ✅ **Self-suspend blocked**: Admin cannot suspend/demote themselves or other admins (views.py:2433-2434) — intentional

### Upload / Media
- ✅ **_sanitize_media_url**: Blocks `javascript:`, `data:` (except raster base64 images), `//` protocol-relative URLs (views.py:190-208)
- ✅ **Allowed formats**: Only data:image/(png|jpeg|jpg|webp|gif);base64 — no SVG, no data:text/html
- ✅ **HTTPS only**: External URLs must start with `https://` and have a valid netloc
- ✅ **Relative paths**: Only single-slash `/path` allowed, `//evil.com` blocked
- ✅ **Size limit**: 600,000 chars max (views.py:198) — combined with DATA_UPLOAD_MAX_MEMORY_SIZE 2.5 MB
- ✅ **No SSRF**: Server never fetches URLs — only stores/returns them. Frontend renders via `<img src>` (React JSX, XSS-safe by default)

### Reviews / Meetups / Chat / Support / Push
- ✅ **create_review_view**: IDOR protected (_is_order_owner), one-review-per-order (Review.order_id unique), collected-only, rate-limited (views.py:2062-2111)
- ✅ **Self-review blocked**: Cannot order from own kitchen (views.py:1143-1144)
- ✅ **propose_meetup_view**: Participant check, payment-required, rate limited, input length capped (views.py:1715-1751)
- ✅ **send_order_message_view**: Participant check, 100-message cap, 500-char limit, HTML stripped, rate limited (views.py:1816-1852)
- ✅ **support_cases_view**: User can only attach own orders (_is_order_participant check at 2279), rate limited 10/hr, duplicate case prevention (2283-2284)
- ✅ **support_case_resolve_view**: Admin-only, AuditEntry snapshot written before case.delete() inside atomic block (views.py:2370-2379) — data not lost
- ✅ **subscribe_push_view**: Endpoint validated (https:// required), cross-user hijack prevented (views.py:2460-2481)

### Models & Constraints
- ✅ **Money fields**: All DecimalField(max_digits=10, decimal_places=2) — subtotal, fee, total, settlement_net, payout amount
- ✅ **CheckConstraints**: meal_price_gte_0_50, meal_left_non_negative, order_subtotal/fee/total/settlement_net_non_negative, review_rating_1_to_5, payout_batch_amount_non_negative
- ✅ **payment_reference**: unique=True, db_index=True (models.py:154)
- ✅ **Review.order_id**: unique=True — enforces one review per order at DB level (models.py:186)
- ✅ **RateLimitBucket.key**: CharField(max_length=255, primary_key=True) — bounded

### Frontend
- ✅ **No dangerouslySetInnerHTML**: React renders all user data via JSX (safe by default)
- ✅ **JWT handling**: Token in localStorage, sent as `Authorization: Bearer` header (api.js:21-28), never in URL
- ✅ **Logout cleanup**: Clears all `stew.*` localStorage keys (Providers.jsx:138), calls server revoke first (136)
- ✅ **sanitizeCachedUser**: Strips password, verification_code_hash, reset_code_hash, login_code_hash before caching (Providers.jsx:55-82)
- ✅ **Mock guard**: Production builds fail without VITE_API_URL (vite.config.js:6-22)
- ✅ **Mixed content warning**: Warns when HTTPS frontend calls HTTP API (api.js:12-14)
- ✅ **Service worker**: Only caches static assets via precacheAndRoute, navigation route excludes /api (sw.js:16-20). No authenticated API responses cached.
- ✅ **Analytics**: Respects DNT, strips IDs from paths (analytics.js:3-7), no PII
- ✅ **VITE_ env vars**: Only VITE_API_URL and VITE_PAYSTACK_PUBLIC_KEY exposed — both safe for browser
- ✅ **Source maps**: Disabled in prod builds (vite.config.js:27)
- ✅ **console.error/warn**: Only infrastructure warnings (api.js:10, 13) — no tokens/PII logged

---

## Not Reviewed (out of scope or budget)

- Paystack webhook signature, payment verification, escrow release, handoff code, refund/payout batching — covered by first Opus review
- JWT core (signing, decoding, revocation, password fingerprint) — covered by first Opus review
- Django admin panel (`/admin/`) — not part of STEW's student-facing app
- Deployment config (nginx, Caddy, Docker, CI/CD) — not in repo
- Third-party dependency vulnerabilities (npm audit, pip-audit) — requires installation
- Load testing / actual concurrency stress testing
- Mobile-specific attack vectors (deep links, intent hijacking)
- Individual frontend component files beyond auth/api/config/sw

---

## Work Order for Gemini (priority order)

1. **S2-01** (Medium): Change `Vendor.rating` from FloatField to `DecimalField(max_digits=3, decimal_places=1)`. Generate migration. Update any `round()` calls.
2. **S2-05** (Low): Add a `cleanup_rate_limits` management command or scheduled task to delete `RateLimitBucket` rows older than their window (e.g., 1 hour). Consider dropping `_RATE_LIMIT_CACHE` in-memory dict since it's redundant with DB.
3. **S2-04** (Low): Remove `SECURE_BROWSER_XSS_FILTER = True` from settings.py. It's a no-op.
4. **S2-02** (Low): In api.js, add `console.warn('[STEW] Running in MOCK mode — no backend connection')` when MOCK activates.
5. **S2-07** (Info): Add `db_index=True` to `Vendor.active` if anticipating growth.
