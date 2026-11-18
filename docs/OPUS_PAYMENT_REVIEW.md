# OPUS Payment & Security Review — STEW Backend

**Branch:** `security/final`  
**Reviewer:** Claude Opus (read-only)  
**Date:** 2026-11-18  
**Scope:** Paystack payments, escrow, order lifecycle, auth core  

---

## 1. Findings (sorted by severity)

| ID | Sev | File:Line | Evidence | Exploit / Failure | Fix | Test |
|----|-----|-----------|----------|-------------------|-----|------|
| H-01 | HIGH | views.py:1614-1638 | `_release_escrow` sets `payment_status='released'`, `settlement_status='released'` without checking current `payment_status`. Trusts caller. | If a future caller omits the `payment_status not in ['paid','released']` guard, escrow releases on an unpaid or already-refunded order. Defence-in-depth violation. | Add `if order.payment_status not in ('paid',): return` at top of `_release_escrow`, or assert and raise. | Call `_release_escrow` on an order with `payment_status='pending'`; assert no state change. |
| H-02 | HIGH | security.py:94-116 | `revoke_jwt_token` writes to `RateLimitBucket`; `is_jwt_revoked` queries it on **every authenticated request** (authentication.py:25). No TTL, no cleanup. | Each logout adds a row. After months, `RateLimitBucket` grows unboundedly; `is_jwt_revoked` does an indexed lookup per request but the table bloats. No periodic purge. Combined with rate-limit entries from every rate-limited action, table reaches millions of rows. | Add a management command or cron to `DELETE FROM api_ratelimitbucket WHERE window_start < NOW() - INTERVAL '48 hours'` for rate-limit rows, and `> JWT lifetime` for revocation rows. Or add a `expires_at` column. | Insert 100k stale rows; verify cleanup removes them; verify `is_jwt_revoked` still works for recent tokens. |
| H-03 | HIGH | views.py:1789-1823 | `set_prep_stage_view` reads order at line 1792 with plain `get()` (no `select_for_update`, no `transaction.atomic`). Writes at 1822 with `save(update_fields=...)`. | Two concurrent requests (e.g. vendor taps "cooking" twice quickly) can TOCTOU: both read stage='accepted', both overwrite to different values. Last write wins, `prep_at` timestamps may be inconsistent. Under PostgreSQL with concurrent workers this is a real race. | Wrap in `transaction.atomic()` + `select_for_update()`. | Two threads: T1 sets 'cooking', T2 sets 'packing', both starting from 'accepted'. Assert final state is deterministic (one wins, the other sees updated state or retries). |
| M-01 | MEDIUM | views.py:1127 | `'price': float(line_price)` stores price as float in the `lines` JSON field, then line 1141 reconstructs with `Decimal(str(line['price']))`. | `float(Decimal('0.01'))` → `0.01` → `str` → `Decimal('0.01')` works for 2-decimal food prices, but the float round-trip is fragile. If a future price like `Decimal('10.005')` bypasses quantize, `float(10.005)` → `str` → `'10.005'` could cause a 1-pesewa drift in subtotal. Stored `total`/`subtotal` Decimal fields are correct; only the JSON `lines` field is affected. | Store `str(line_price)` instead of `float(line_price)` in the dict. | Create order with price=GHS 7.77, qty=3; assert `lines[0]['price']` is `'7.77'` (string) and `order.subtotal == Decimal('23.31')`. |
| M-02 | MEDIUM | security.py:51,63 | `_JWT_LIFETIME_HOURS = 24`. No refresh token. Comment at line 50 says "consider 1 hour + refresh token". | A stolen JWT is valid for 24 hours. Password change invalidates it (via `pv` fingerprint), but session theft window is large. | Reduce to 1–4 hours and add refresh token, or accept the risk and document it. | N/A (design decision). |
| M-03 | MEDIUM | views.py:1812 | `valid_stages = ['accepted', 'shopping', 'cooking', 'packing', 'ready']`. No ordering enforcement. | Vendor can regress from 'ready' back to 'accepted'. Frontend timestamps in `prep_at` would show nonsensical ordering. May confuse support and audit. | Either enforce `STAGE_ORDER.index(new) > STAGE_ORDER.index(current)` or document as intentional (chef can correct mistakes). | Set stage to 'ready', then to 'accepted'; assert rejection or document acceptance. |
| M-04 | MEDIUM | views.py:2262 | `case.delete()` on resolution. No soft-delete or resolved state. | Resolved support cases vanish from DB. Only evidence is `AuditEntry`. If audit entries are lost or query is slow, there's no way to review past resolutions. Cannot re-open a case. | Change to `case.status = 'resolved'`/`'dismissed'` + `case.resolved_at = now` instead of delete. | Resolve a case; assert it still exists with status='resolved'. |
| M-05 | MEDIUM | views.py:320 | Rate limit key `f"reg_{ip}"` uses `request.META.get('REMOTE_ADDR', '127.0.0.1')`. | Behind a load balancer that doesn't rewrite `REMOTE_ADDR`, all registrations share one rate-limit bucket (the proxy IP). An attacker on campus Wi-Fi behind NAT would share a bucket with legitimate users. | Use `X-Forwarded-For` with a trusted-proxy allowlist, or document that the deployment's reverse proxy must set `REMOTE_ADDR`. | Send 11 registrations from same IP; assert 11th is rate-limited. Send from different IP; assert allowed. |
| M-06 | MEDIUM | views.py:1444 | `verify_payment_view` reads order without `select_for_update`. Checks `payment_status` and `payment_reference` on a stale snapshot before calling `_paystack_verify` (HTTP) and `_mark_order_paid` (which re-locks). | Between line 1444 and 1473, a concurrent `cancel_order_view` could cancel the order. `_mark_order_paid` correctly detects `cancelled_at` under its own lock and returns early. But the view returns `200` with the order serialized from `_mark_order_paid`'s return (cancelled state), which the client may misinterpret as "payment verified". | Either wrap the whole view in `atomic()` + `select_for_update()` (and do the Paystack HTTP call outside the lock like `init_payment_view` does), or return the locked order's payment_status and 400 if not 'paid'. | Concurrency test: T1 calls verify_payment while T2 cancels the order. Assert response reflects cancellation. |
| L-01 | LOW | security.py:64-71 | JWT payload lacks `iss` and `aud` claims. | A JWT from another application sharing the same `SECRET_KEY` would be accepted. Single-app deployment makes this theoretical. | Add `'iss': 'stew'` and validate on decode with `options={'require': ['iss']}`. | Craft JWT with wrong `iss`; assert rejection. |
| L-02 | LOW | views.py:436-437 | After email verification, `hash_token(code)` is reused as `login_code_hash` with 2-minute TTL. | The same 6-digit OTP serves double duty: verification + auto-login. The 2-minute window is tight and the code is consumed on use (line 590-592). Acceptable UX trade-off. | Document as intentional. | Verify email, then login_with_code with same code within 2 min; assert success. After 2 min; assert failure. |
| L-03 | LOW | views.py:1568 | `week_total = round(float(...), 2)` in `payouts_ledger_view` converts Decimal aggregate to float for JSON. | For typical campus order volumes, float precision loss is sub-pesewa and display-only. Stored fields remain Decimal. | Use `str(Decimal(...))` or `float(Decimal(...).quantize(...))` for explicit rounding. | Assert ledger `weekTotal` matches expected Decimal sum for a set of test orders. |


---

## 2. Checked and Fine

| Area | File:Line | Notes |
|------|-----------|-------|
| Webhook HMAC signature | views.py:1490-1491 | `hmac.new()` over `request.body` (raw), `hmac.compare_digest()` (constant-time). Missing header/key → 400. CONFIRMED safe. |
| Webhook idempotency | views.py:1500-1523 → _mark_order_paid:1380-1391 | `_mark_order_paid` uses `select_for_update`, checks `cancelled_at` and `payment_status in ('paid','released')` before writing. Duplicate webhooks are no-ops. CONFIRMED. |
| Webhook amount/currency/status | views.py:1504-1519 | Checks `ev_status == 'success'`, `ev_currency == 'GHS'`, `ev_amount >= expected_pesewas`. Pesewas conversion correct: `Decimal(str(order.total)) * 100` with `ROUND_HALF_UP`. Then re-verifies with Paystack API (line 1521). CONFIRMED. |
| Webhook re-verification | views.py:1521 | Webhook does NOT trust payload alone — calls `_paystack_verify(reference, order)` which hits Paystack API and re-checks status, reference, currency, amount. CONFIRMED. |
| _paystack_verify amount check | views.py:1413-1421 | `tx_amount < expected_pesewas` rejects underpayment. Overpayment accepted (correct — Paystack rounds up). Reference and currency matched. CONFIRMED. |
| init_payment server-side amount | views.py:1302 | Amount from `order.total` (server-side Decimal), never from client. CONFIRMED. |
| init_payment row lock | views.py:1285-1287 | `transaction.atomic()` + `select_for_update()`. Re-locks at lines 1356-1364 after external HTTP call. CONFIRMED. |
| init_payment reference reuse | views.py:1303,1313-1316,1327-1331,1360-1364 | Existing reference reused; new reference only if none exists. Second lock at 1356 prevents race on reference assignment. CONFIRMED. |
| _paystack_mock_allowed | views.py:252-253 | `DEBUG=True AND PAYSTACK_ALLOW_MOCK=True` both required. Production (`DEBUG=False`) cannot enable mock. CONFIRMED. |
| Order creation server-side pricing | views.py:1111-1120 | `db_meal = Meal.objects.select_related('vendor').filter(id=meal_id_str).first()` — price, name, vendor always from DB. Client-supplied price ignored. CONFIRMED. |
| Order creation cross-vendor block | views.py:1116-1119 | Rejects lines from different vendors. CONFIRMED. |
| Order creation stock lock ordering | views.py:1159-1161 | `sorted(requested_qty.keys())` + `select_for_update().order_by('id')`. Consistent ascending PK order prevents deadlocks. CONFIRMED. |
| Order creation Decimal arithmetic | views.py:1120,1141-1146 | `Decimal(str(db_meal.price)).quantize(...)`, `sum(Decimal * Decimal)`, fee and total quantized to 0.01. No float in stored totals. CONFIRMED. |
| Order creation self-order block | views.py:1137-1138 | Vendor can't order from own kitchen. CONFIRMED. |
| Order creation qty limits | views.py:1094-1096,1107,1122-1123 | Max 20 lines, qty 1-50 via `_safe_int`, aggregate max 50 per meal. CONFIRMED. |
| cancel_order_view row lock | views.py:1230-1232 | `transaction.atomic()` + `select_for_update()`. CONFIRMED. |
| cancel_order_view state guards | views.py:1241-1252 | Rejects already-cancelled, already-collected. Student: only if stage='accepted' and within 120s. Vendor/admin: any non-terminal. CONFIRMED. |
| cancel_order_view refund states | views.py:1255-1261 | `paid+released_settlement` → `refund_pending`; `paid+not_released` → `refunded`; `unpaid` → `cancelled`. Correct escrow semantics. CONFIRMED. |
| _restore_order_stock idempotency | views.py:114-138 | `prep_at['_stockRestored']` flag prevents double-restore. `select_for_update` on order. Meal locks in sorted order. CONFIRMED. |
| mark_collected_view | views.py:1836-1854 | `select_for_update`, IDOR check (owner or admin only), checks cancelled/unpaid/already-collected. Vendor CANNOT call this endpoint (IsStudentUser permission). CONFIRMED. |
| complete_by_code_view | views.py:1867-1908 | `select_for_update`, vendor-or-admin only, cancelled/unpaid/collected guards, 14-day expiry, rate limit (5/600s per order), code rotation on lockout, `secrets.compare_digest` for constant-time comparison. CONFIRMED. |
| Handoff code entropy | security.py:44-46 | `secrets.randbelow(900000) + 100000` → 6 digits, 900k possibilities. Cryptographically random. CONFIRMED. |
| Handoff code visibility | serializers.py:165-168 | `get_handoffCode` returns code only to `_is_owner_or_admin`, not vendor. Cleared on collection (views.py:1633). CONFIRMED. |
| Handoff code single-use | views.py:1633 | `order.handoff_code = ''` after `_release_escrow`. Cannot reuse. CONFIRMED. |
| Double-resolution prevention | views.py:2232-2262 | `select_for_update` on SupportCase. Second concurrent request blocks; after first commits (deletes case), second gets DoesNotExist. CONFIRMED. |
| Payout batch guard on refund | views.py:2240-2244 | Returns 409 if `order.payout_batch_id` is set. CONFIRMED. |
| Payout double-batch prevention | views.py:2134-2144 | `payout_batch_id__isnull=True` filter + `select_for_update().order_by('id')`. Consistent lock ordering. Only active vendors. CONFIRMED. |
| Payout aggregates over full set | views.py:1557-1564 | `aggregate()` on full queryset, not paginated subset. CONFIRMED. |
| JWT algorithm pinned | security.py:72,78 | `algorithm='HS256'` on encode, `algorithms=['HS256']` on decode. No algorithm confusion. CONFIRMED. |
| JWT revocation on every request | authentication.py:25 | `is_jwt_revoked(token, payload)` called before user lookup. CONFIRMED. |
| JWT password-change invalidation | authentication.py:38 | `password_fingerprint(user)` compared to `payload['pv']`. Password change → all old tokens rejected. CONFIRMED. |
| is_active + verified enforced | authentication.py:33 | `User.objects.get(id=user_id, is_active=True, verified=True)`. CONFIRMED. |
| KNUST email enforcement | authentication.py:42-43 | Regex check on every authenticated request. CONFIRMED. |
| Registration mass-assignment prevention | serializers.py:43-54 | `RegisterSerializer` is a plain `Serializer` (not ModelSerializer), defines exact fields. `accountType` choices: `['customer','vendor','both']` — no 'admin'. `is_admin`, `is_staff`, `verified` are NOT serializer fields → cannot be injected. Views.py:360-375 passes only validated fields to `create_user`, explicitly sets `verified=False`. CONFIRMED. |
| Login rate limiting | views.py:506 | `f"login_{email}"` after `clean_knust_email` normalizes to lowercase. Case variation bypass impossible. CONFIRMED. |
| OTP brute-force protection | views.py:414,570 | 5 attempts / 10 min; code hash burned on lockout (lines 415, 571). CONFIRMED. |
| OTP hashing | security.py:30-33,36-41 | SHA-256 with salt; constant-time verification via `hmac.compare_digest`. CONFIRMED. |
| OTP single-use | views.py:433-434,590-592 | Verification code cleared after use; login code cleared after use. CONFIRMED. |
| Rate limiting DB-backed | security.py:135-173 | `select_for_update()` inside `transaction.atomic()`. Survives restarts. Works across workers. CONFIRMED. |
| Logout revocation | views.py:768-773 | `revoke_jwt_token(str(request.auth))` persists jti to DB. CONFIRMED. |
| CSP / Permissions-Policy | security.py:119-132 | `default-src 'none'` on API routes; `frame-ancestors 'none'` everywhere. CONFIRMED. |

---

## 3. Not Reviewed

| Area | Reason |
|------|--------|
| Frontend (stew repo) | Out of scope per instructions |
| Django admin panel security (`/admin/`) | Not in scope; CSP header applied (checked) |
| Email sending (`_dispatch_otp_email`) | Utility function, not payment-critical |
| Push notification (`subscribe_push_view`) | Not payment-critical |
| Analytics (`analytics_event_view`) | Not payment-critical |
| File upload / media validation | Not in payment/auth scope |
| Meetup workflow (propose/confirm/decline) | Not escrow-critical |
| Review/rating workflow | Not payment-critical |
| Admin vendor/user management | Not directly payment-critical |
| `vendor_apply_view`, `vendor_activate_view` | Vendor onboarding, not in top-8 |
| Django settings (`settings.py`) | Partially checked (DEBUG, SECRET_KEY usage observed); CORS, ALLOWED_HOSTS, database config not reviewed |
| Model-level constraints / migrations | Not reviewed (read-only, no migration runs) |
| Test suite | Not reviewed per instructions |

---

## 4. Gemini Work Order (ordered fixes with acceptance tests)

### Priority 1 — Do before launch

1. **H-01: Add payment_status guard to `_release_escrow`**
   - At top of `_release_escrow`, add: `if order.payment_status not in ('paid',): raise ValueError(f"Cannot release escrow on order {order.id} with payment_status={order.payment_status}")`
   - *Test:* Call `_release_escrow` on order with `payment_status='pending'`; assert `ValueError` raised and no DB changes.

2. **H-02: Add RateLimitBucket cleanup**
   - Add management command `cleanup_rate_limits` that deletes rows older than 48 hours (rate limits) and older than JWT lifetime + 1 hour (revocations).
   - Add `expires_at` column (nullable) to `RateLimitBucket`; set it in `revoke_jwt_token` to `now + lifetime`.
   - *Test:* Insert 1000 stale rows; run cleanup; assert deleted. Insert fresh revocation; assert still exists. Verify `is_jwt_revoked` performance with 100k rows.

3. **H-03: Add row lock to `set_prep_stage_view`**
   - Wrap body in `with transaction.atomic():` and change `Order.objects.get(id=pk)` to `Order.objects.select_for_update().get(id=pk)`.
   - *Test:* Two concurrent threads set different stages on same order; assert no lost update.

### Priority 2 — Before scaling

4. **M-01: Store price as string in order lines JSON**
   - Change line 1127 from `'price': float(line_price)` to `'price': str(line_price)`.
   - Update any code reading `line['price']` to handle string.
   - *Test:* Create order; assert `order.lines[0]['price']` is a string; assert `order.subtotal` matches expected Decimal.

5. **M-06: Lock order in verify_payment_view or return correct status**
   - After `_mark_order_paid`, check `order.payment_status == 'paid'`; if not, return 400 with appropriate message.
   - *Test:* Race cancel_order_view against verify_payment_view; assert response status reflects cancellation.

6. **M-04: Soft-delete support cases instead of hard delete**
   - Add `status` field (open/resolved/dismissed) and `resolved_at` timestamp. Replace `case.delete()` with status update.
   - *Test:* Resolve case; assert still in DB with `status='resolved'`.

### Priority 3 — Hardening

7. **M-02: Reduce JWT lifetime**
   - Set `JWT_ACCESS_TOKEN_LIFETIME_HOURS = 4` (or 1 with refresh tokens).
   - *Test:* Generate token; assert expiry is 4 hours from now.

8. **M-03: Enforce prep stage ordering (or document as intentional)**
   - Either validate `STAGE_ORDER.index(new) >= STAGE_ORDER.index(current)` or add comment documenting backward transitions are allowed.
   - *Test:* Set 'ready' then 'accepted'; assert rejection (if enforcing) or document.

9. **M-05: Document REMOTE_ADDR proxy requirement**
   - Add to `PRODUCTION_PREFLIGHT.md`: "Verify that the reverse proxy sets `REMOTE_ADDR` to the real client IP."

10. **L-01: Add `iss` claim to JWT**
    - Add `'iss': 'stew'` to payload; add `issuer='stew'` to `jwt.decode()`.
    - *Test:* Craft JWT with `iss='other'`; assert rejection.
