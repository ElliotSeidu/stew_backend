# STEW Pre-Production Database Preflight Checks

Run EVERY check below against a **restore/copy of the production PostgreSQL database** (and read-only against production if needed — every query below is strictly `SELECT` / ORM read-only) **before** applying migrations `0003+` and deploying `security/final`.

Do not run cleanup `UPDATE`s directly on production without backing up first and testing the identical steps on the restored copy.

---

## 1. `payment_reference` Integrity (`api_order`)

Migration `0003_decimal_money_and_constraints` converts blank `payment_reference` values to `NULL`, enforces `UNIQUE (payment_reference)` (`max_length=128`), and deduplicates collisions. Inspect what exists first so no Paystack reconciliation link is unexpectedly renamed.

### PostgreSQL SQL (Read-Only)
```sql
-- 1a. Blank, whitespace-only, or oversized (> 128 chars) payment_reference rows
SELECT id, email, payment_status, payment_provider,
       COALESCE(payment_reference, '<NULL>') AS payment_reference,
       LENGTH(payment_reference) AS ref_len,
       created_at
FROM api_order
WHERE payment_reference IS NULL
   OR BTRIM(payment_reference) = ''
   OR LENGTH(payment_reference) > 128
ORDER BY created_at ASC;

-- 1b. Duplicate non-blank payment_reference values (including collisions modulo whitespace)
SELECT BTRIM(payment_reference) AS normalized_ref,
       COUNT(*) AS row_count,
       ARRAY_AGG(id ORDER BY created_at, id) AS order_ids,
       ARRAY_AGG(LEFT(id, 8) ORDER BY created_at, id) AS id_prefixes,
       ARRAY_AGG(payment_status ORDER BY created_at, id) AS payment_statuses
FROM api_order
WHERE payment_reference IS NOT NULL
  AND BTRIM(payment_reference) <> ''
GROUP BY BTRIM(payment_reference)
HAVING COUNT(*) > 1
ORDER BY row_count DESC;
```

### Django Shell (Read-Only)
```python
from django.db.models import Count
from api.models import Order

blank_refs = list(
    Order.objects.filter(payment_reference='').values_list('id', 'payment_status', 'created_at')
)
ws_or_long = [
    (o.id, o.payment_status, len(o.payment_reference))
    for o in Order.objects.exclude(payment_reference__isnull=True).only('id', 'payment_status', 'payment_reference')
    if not o.payment_reference.strip() or len(o.payment_reference) > 128
]
dupes = list(
    Order.objects.exclude(payment_reference__isnull=True)
    .exclude(payment_reference='')
    .values('payment_reference')
    .annotate(c=Count('id'))
    .filter(c__gt=1)
)
print({'blank_count': len(blank_refs), 'ws_or_long': ws_or_long, 'duplicates': dupes})
```

### What Results Mean & Remediation
- **`NULL`**: Expected for unpaid/uninitialized orders; PostgreSQL `UNIQUE` allows multiple `NULL` rows. Safe.
- **`''` or whitespace (`'   '`)**: Pre-`0003` code sometimes stored `''`. Migration `0003` converts blank strings to `NULL`.
- **`ref_len > 128`**: Migration `0003` truncates to 128 chars; verify against Paystack dashboard logs before migrating so no real Paystack reference is truncated.
- **Duplicate non-blank references (`row_count > 1`)**: Indicates either a split-checkout bug, retry race, or manual DB edit. Reconcile the duplicate order IDs in Paystack first: confirm which `Order` actually received payment, cancel/close stale duplicates, or allow `0003` to suffix later rows with `-DUP<n>-<id[:8]>` (recorded for audit).

---

## 2. Rows Violating New `0003` `CheckConstraint`s or `NUMERIC(10, 2)` Bounds

Migration `0003` switches float/money columns to `DECIMAL(10, 2)` (max `99999999.99`) and adds **8** `CheckConstraint`s:
1. `meal_price_gte_0_50` (`api_meal.price >= 0.50`)
2. `meal_left_non_negative` (`api_meal.left >= 0`)
3. `order_subtotal_non_negative` (`api_order.subtotal >= 0.00`)
4. `order_fee_non_negative` (`api_order.fee >= 0.00`)
5. `order_total_non_negative` (`api_order.total >= 0.00`)
6. `order_settlement_net_non_negative` (`api_order.settlement_net >= 0.00`)
7. `payout_batch_amount_non_negative` (`api_payoutbatch.amount >= 0.00`)
8. `review_rating_1_to_5` (`api_review.rating BETWEEN 1 AND 5`)

### PostgreSQL SQL (Read-Only)
```sql
-- 2a. api_meal constraint & numeric-bound violations (works pre-0003 or post-0003)
SELECT id, vendor_id, name, price::text, "left",
       (price::text IN ('NaN', 'Infinity', '-Infinity')) AS is_non_finite
FROM api_meal
WHERE price::text IN ('NaN', 'Infinity', '-Infinity')
   OR price < 0.50
   OR price > 99999999.99
   OR "left" < 0;

-- 2b. api_order constraint & numeric-bound violations
SELECT id, email, payment_status, subtotal::text, fee::text, total::text, settlement_net::text
FROM api_order
WHERE subtotal::text IN ('NaN', 'Infinity', '-Infinity')
   OR fee::text IN ('NaN', 'Infinity', '-Infinity')
   OR total::text IN ('NaN', 'Infinity', '-Infinity')
   OR settlement_net::text IN ('NaN', 'Infinity', '-Infinity')
   OR subtotal < 0 OR fee < 0 OR total < 0 OR settlement_net < 0
   OR subtotal > 99999999.99 OR fee > 99999999.99
   OR total > 99999999.99 OR settlement_net > 99999999.99;

-- 2c. api_payoutbatch constraint & numeric-bound violations
SELECT id, status, order_count, amount::text
FROM api_payoutbatch
WHERE amount::text IN ('NaN', 'Infinity', '-Infinity')
   OR amount < 0
   OR amount > 99999999.99;

-- 2d. api_review constraint violations
SELECT id, order_id, vendor_id, rating, moderation_status
FROM api_review
WHERE rating < 1 OR rating > 5 OR rating IS NULL;
```

### Django Shell (Read-Only)
```python
from decimal import Decimal
from django.db.models import Q
from api.models import Meal, Order, PayoutBatch, Review

bad_meals = list(Meal.objects.filter(Q(price__lt=Decimal('0.50')) | Q(left__lt=0)).values('id', 'price', 'left'))
bad_orders = list(
    Order.objects.filter(
        Q(subtotal__lt=0) | Q(fee__lt=0) | Q(total__lt=0) | Q(settlement_net__lt=0)
    ).values('id', 'subtotal', 'fee', 'total', 'settlement_net', 'payment_status')
)
bad_batches = list(PayoutBatch.objects.filter(amount__lt=0).values('id', 'amount', 'status'))
bad_reviews = list(Review.objects.filter(Q(rating__lt=1) | Q(rating__gt=5)).values('id', 'order_id', 'rating'))
print({'bad_meals': bad_meals, 'bad_orders': bad_orders, 'bad_batches': bad_batches, 'bad_reviews': bad_reviews})
```

### What Results Mean & Remediation
- **Any non-zero count**: Without `0003` data normalization, `ADD CONSTRAINT` / `ALTER TYPE NUMERIC(10,2)` fails with `CheckViolation`, `InvalidOperation`, or `NumericValueOutOfRange`.
- **Action**: Inspect every flagged row on the copy first! Hardened `0003` will clamp non-finite/negative meal prices to `0.50`, negative stock to `0`, negative/non-finite order/batch money to `0.00` (and values `> 99999999.99` to `99999999.99`), and ratings into `1..5`. If a real corrupted financial record appears (e.g. a real order with negative total or > GHS 99M), fix or archive the root record manually before deploying.

---

## 3. Users with `verified = FALSE` (Admins, Vendors & Order Holders)

`JWTAuthentication`, login-code authentication, `IsStudentUser`, and `IsVendorUser` require `user.verified = True` and `user.is_active = True`. Any legitimate user with `verified = False` will be denied API access (`401`/`403`) until verified via email OTP.

### PostgreSQL SQL (Read-Only)
```sql
SELECT u.id, u.email, u.full_name, u.is_admin, u.is_staff, u.is_vendor,
       u.role, u.account_type, u.is_active, u.verified, u.created_at,
       EXISTS (SELECT 1 FROM api_vendor v WHERE v.user_id = u.id) AS has_vendor_row,
       (SELECT COUNT(*) FROM api_order o WHERE o.customer_id = u.id OR o.email = u.email) AS order_count
FROM api_user u
WHERE u.verified = FALSE
ORDER BY u.is_admin DESC, u.is_vendor DESC, u.created_at DESC;
```

### Django Shell (Read-Only)
```python
from api.models import User, Vendor, Order

for u in User.objects.filter(verified=False).order_by('-is_admin', '-is_vendor', '-created_at'):
    has_v = Vendor.objects.filter(user=u).exists()
    ord_c = Order.objects.filter(customer=u).count()
    print(u.id, u.email, 'admin=', u.is_admin, 'staff=', u.is_staff, 'vendor=', u.is_vendor, 'has_vendor_row=', has_v, 'orders=', ord_c)
```

### What Results Mean & Remediation
- **Unverified admins (`is_admin = TRUE` and `verified = FALSE`)**: Locked out of admin login/JWT until verified! Confirm ownership out-of-band, then set `verified = True` on genuine ops admins before go-live (or deactivate bogus rows).
- **Unverified vendors with active kitchens (`has_vendor_row = TRUE` and `verified = FALSE`)**: Cannot access vendor endpoints via JWT (`401`). If their email wasn't verified during legacy onboarding, verify their KNUST email address or require them to run `resend-code` -> `verify-email`.
- **Unverified students with paid orders (`order_count > 0` and `verified = FALSE`)**: Will be unable to view orders/handoff codes until they complete OTP email verification. Notify or trigger password/email verification.

---

## 4. Admin Privilege Tightening (`is_platform_admin(user) == user.is_admin`)

Under the single canonical definition `is_platform_admin(user) == bool(user and user.is_authenticated and user.is_admin)`:
- `is_staff`, `role='admin'`, and `account_type='admin'` **grant zero admin privileges** in the API (and `/admin/` itself now also requires `is_admin=True` + `verified=True`).

### PostgreSQL SQL (Read-Only)
```sql
-- 4a. Legacy/partial-admin users who WILL LOSE admin access (is_admin = FALSE)
SELECT id, email, full_name, is_admin, is_staff, is_superuser, role, account_type, is_active, verified, created_at
FROM api_user
WHERE is_admin = FALSE
  AND (is_staff = TRUE OR is_superuser = TRUE OR role = 'admin' OR account_type = 'admin')
ORDER BY created_at ASC;

-- 4b. All users who CURRENTLY HOLD platform admin access (is_admin = TRUE)
SELECT id, email, full_name, is_admin, is_staff, is_superuser, role, account_type, is_active, verified, created_at
FROM api_user
WHERE is_admin = TRUE
ORDER BY created_at ASC;
```

### Django Shell (Read-Only)
```python
from django.db.models import Q
from api.models import User

print('--- WOULD LOSE ADMIN ACCESS ---')
for u in User.objects.filter(is_admin=False).filter(
    Q(is_staff=True) | Q(is_superuser=True) | Q(role='admin') | Q(account_type='admin')
):
    print(u.id, u.email, 'staff=', u.is_staff, 'su=', u.is_superuser, 'role=', u.role, 'acct=', u.account_type, 'verified=', u.verified)

print('--- CURRENT is_admin=True ---')
for u in User.objects.filter(is_admin=True):
    print(u.id, u.email, 'active=', u.is_active, 'verified=', u.verified)
```

### What Results Mean & Remediation
- **Query 4a non-empty**: Any real administrator listed here MUST have `is_admin = True` (and `verified = True, is_active = True`) set **before** deploying, or they will get `403 Forbidden` on every admin endpoint! Conversely, any accidental `role='admin'` / `is_staff=True` test account should have those legacy flags cleared (`role='customer'`, `account_type='customer'`, `is_staff=False`).
- **Query 4b check**: Confirm EVERY row is an authorized campus operations operator; revoke `is_admin = False` on any seeded demo/test admin (such as `admin@st.knust.edu.gh` if seeded locally) before go-live.

---

## 5. Vendor Matrix (`active`, `open`, `user.verified`, `api_compliance`)

### PostgreSQL SQL (Read-Only)
```sql
-- 5a. Breakdown by state
SELECT v.active, v.open, COALESCE(u.verified, FALSE) AS user_verified,
       COALESCE(u.is_active, FALSE) AS user_active,
       (c.id IS NOT NULL) AS has_compliance,
       COUNT(*) AS vendor_count
FROM api_vendor v
LEFT JOIN api_user u ON u.id = v.user_id
LEFT JOIN api_compliance c ON c.vendor_id = u.email
GROUP BY 1, 2, 3, 4, 5
ORDER BY vendor_count DESC;

-- 5b. Detailed list of inactive, unverified, or ownerless kitchens
SELECT v.id, v.name, v.hall, v.active, v.open,
       u.email AS owner_email, u.verified AS user_verified, u.is_active AS user_active,
       c.number AS permit_number, c.expires_at AS permit_expires
FROM api_vendor v
LEFT JOIN api_user u ON u.id = v.user_id
LEFT JOIN api_compliance c ON c.vendor_id = u.email
WHERE v.active = FALSE OR COALESCE(u.verified, FALSE) = FALSE OR u.id IS NULL
ORDER BY v.created_at DESC;
```

### Django Shell (Read-Only)
```python
from api.models import Compliance, Vendor

for v in Vendor.objects.select_related('user').all():
    owner = v.user
    comp = Compliance.objects.filter(vendor_id=owner.email).first() if owner else None
    print(
        v.id, v.name,
        f"active={v.active}", f"open={v.open}",
        f"owner_verified={getattr(owner, 'verified', None)}",
        f"owner_active={getattr(owner, 'is_active', None)}",
        f"compliance={'yes' if comp else 'no'}",
    )
```

### Capabilities by State (Verified Against Code)
| `user.verified` & `user.is_active` | `vendor.active` | `vendor.open` | What the vendor **can** do | What is **blocked** |
|---|---|---|---|---|
| `True`, `True` | `True` | `True` | Full kitchen ops: listed in `/api/vendors/`, receive paid orders, mutate `/api/meals/`, advance prep, verify handoff codes, upload compliance, view `/api/payouts/` | Orders cannot be placed for own kitchen |
| `True`, `True` | `True` | `False` | Listed in `/api/vendors/`, mutate `/api/meals/`, upload compliance, complete existing orders, view `/api/payouts/` | New orders blocked (`400`: kitchen not taking orders) |
| `True`, `True` | `False` | any | Read `GET /api/auth/me/`, `GET /api/vendors/<own_id>/`, `GET /api/payouts/`, `GET/POST /api/vendor/compliance/` (pending status check & permit submission allowed; no onboarding deadlock) | Hidden from `/api/vendors/`, blocked (`403`) on `POST/PATCH/DELETE /api/meals/`, prep/complete/nudge/meetup/message on orders, `POST /api/vendor/apply/`, and `POST /api/vendor/activate/`; excluded from `PayoutBatch` creation |
| `False`, `True` | any | any | Request resend/verify email OTP (`POST /api/auth/verify-email/`, `POST /api/auth/resend-code/`) | Rejected (`401`/`403`) by `JWTAuthentication`, `IsStudentUser`, `IsVendorUser` across all authenticated endpoints |
| any, `False` | any | any | Nothing — deactivated user | Blocked at login (`401`), JWT (`401`), and permissions (`403`) |

### What Results Mean & Remediation
- **Orphaned vendor rows (`owner_email IS NULL`)**: Nobody can manage these kitchens. Deactivate (`active = FALSE, open = FALSE`) or link to the valid owner user.
- **Unverified owners with `active = TRUE` kitchens**: Temporarily set `active = FALSE` until owner verifies KNUST email, or coordinate verification.

---

## 6. Orders in Odd or Inconsistent Escrow States (`api_order`)

### PostgreSQL SQL (Read-Only)
```sql
SELECT id, email, vendor_id, payment_status, settlement_status, prep_stage,
       subtotal::text, fee::text, total::text, settlement_net::text,
       payout_batch_id, paid_at, collected_at, cancelled_at, created_at,
       CASE
         WHEN cancelled_at IS NOT NULL AND payment_status IN ('paid', 'released') THEN 'cancelled_still_paid'
         WHEN collected_at IS NOT NULL AND payment_status NOT IN ('paid', 'released') THEN 'collected_but_unpaid'
         WHEN payout_batch_id IS NOT NULL AND (cancelled_at IS NOT NULL OR settlement_status <> 'released' OR collected_at IS NULL) THEN 'bad_payout_batch_link'
         WHEN ABS(total - (subtotal + fee)) > 0.02 THEN 'total_mismatch'
         WHEN payment_status IN ('disputed', 'refund_pending') THEN 'disputed_or_refund_pending'
         WHEN payment_status = 'pending' AND created_at < NOW() - INTERVAL '24 hours' THEN 'stale_pending_gt_24h'
         ELSE 'other_odd_state'
       END AS anomaly
FROM api_order
WHERE (cancelled_at IS NOT NULL AND payment_status IN ('paid', 'released'))
   OR (collected_at IS NOT NULL AND payment_status NOT IN ('paid', 'released'))
   OR (payout_batch_id IS NOT NULL AND (cancelled_at IS NOT NULL OR settlement_status <> 'released' OR collected_at IS NULL))
   OR ABS(total - (subtotal + fee)) > 0.02
   OR payment_status IN ('disputed', 'refund_pending')
   OR payment_status NOT IN ('pending', 'paid', 'released', 'refund_pending', 'refunded', 'cancelled', 'failed')
   OR prep_stage NOT IN ('accepted', 'preparing', 'ready', 'collected')
   OR (payment_status = 'pending' AND created_at < NOW() - INTERVAL '24 hours')
ORDER BY created_at DESC;
```

### Django Shell (Read-Only)
```python
from datetime import timedelta
from django.db.models import F, Q
from django.utils import timezone
from api.models import Order

cutoff = timezone.now() - timedelta(hours=24)
odd_orders = Order.objects.filter(
    Q(cancelled_at__isnull=False, payment_status__in=['paid', 'released'])
    | Q(collected_at__isnull=False) & ~Q(payment_status__in=['paid', 'released'])
    | Q(payout_batch_id__isnull=False) & (Q(cancelled_at__isnull=False) | ~Q(settlement_status='released') | Q(collected_at__isnull=True))
    | Q(payment_status__in=['disputed', 'refund_pending'])
    | ~Q(payment_status__in=['pending', 'paid', 'released', 'refund_pending', 'refunded', 'cancelled', 'failed'])
    | ~Q(prep_stage__in=['accepted', 'preparing', 'ready', 'collected'])
    | Q(payment_status='pending', created_at__lt=cutoff)
)
print('Odd order count:', odd_orders.count())
for o in odd_orders[:50]:
    print(o.id, o.payment_status, o.settlement_status, o.prep_stage, o.payout_batch_id, o.subtotal, o.fee, o.total)
```

### What Results Mean & Remediation
- **`cancelled_still_paid` / `refund_pending`**: Customer cancelled or support opened a refund after escrow release or payment capture. Process the refund on Paystack and update `payment_status = 'refunded'` (never mark paid orders silently cancelled without refunding!).
- **`collected_but_unpaid`**: Critical integrity anomaly — food was marked collected without confirmed Paystack payment. Audit Paystack reference manually immediately.
- **`bad_payout_batch_link`**: An order linked to a `PayoutBatch` is cancelled, uncollected, or not `settlement_status='released'`. Reconcile vendor payout ledger before creating any new `PayoutBatch`.
- **`total_mismatch`**: Recompute `subtotal + fee` vs `total` and verify Paystack amount paid matches.
- **Unrecognized `payment_status` / `prep_stage` (e.g., `'disputed'`)**: Resolve before launch so orders do not sit permanently stuck outside vendor/admin workflow filters.
- **`stale_pending_gt_24h`**: Abandoned checkout orders still holding `Meal.left` stock. Cancel and restore stock (idempotently) if Paystack confirms no payment was captured for `payment_reference`.

---

## 7. Reverse Proxy (`TRUSTED_PROXY_COUNT`) & Campus NAT Rate Limits

All security-critical rate limits (OTP verification, login code, password reset, payment initiation, handoff completion, order creation) are keyed per email, user, or order in PostgreSQL `RateLimitBucket`. The remaining IP-keyed flood guards (`register_view`, `forgot_password_view`, `reset_password_view`, `check_reference_view`, `analytics_event_view`, and DRF `AnonRateThrottle`) extract the client IP using `TRUSTED_PROXY_COUNT` (right-to-left parsing of `X-Forwarded-For`, never trusting the left-most header value) and allow campus-NAT ceilings (`100/hour` on registration/reset, `120/min` on reference-check/analytics, `1000/min` DRF `anon` via `THROTTLE_ANON_PER_MIN`, and `120/min` DRF `user` via `THROTTLE_USER_PER_MIN`).

| Hosting Topology | Required `TRUSTED_PROXY_COUNT` | Reverse Proxy Notes |
|---|---|---|
| Direct Gunicorn or reverse proxy rewrites `REMOTE_ADDR` (e.g. nginx with `set_real_ip_from` / UNIX socket only) | **`0`** *(default)* | Ignores `X-Forwarded-For` completely so spoofed headers have zero effect. |
| Single managed reverse proxy / PaaS LB in front of Gunicorn (Render, Railway, Fly.io, DigitalOcean App Platform, AWS ALB, single nginx/Caddy) | **`1`** | Reads the right-most hop of `X-Forwarded-For` appended by your trusted edge/LB. Ensure Gunicorn is NOT directly reachable from the public internet bypassing the LB. |
| CDN / WAF (e.g. Cloudflare) **in front of** your own nginx / AWS ALB | **`2`** | Counts Cloudflare + your LB from the right (`parts[-2]`). Lock nginx/ALB firewall to Cloudflare IPs so clients cannot inject hops before the LB. |

### Staging Verification: Confirming `TRUSTED_PROXY_COUNT` (Two-Device `429` Check)

Before cutover, verify `TRUSTED_PROXY_COUNT` live on staging with two client devices on different networks so shared proxy IPs can never cause campus-wide lockouts or spoofable rate-limit bypasses:

1. **Lower the staging anonymous throttle temporarily** (requires no code edit): set `THROTTLE_ANON_PER_MIN=10` alongside your candidate `TRUSTED_PROXY_COUNT`, and restart staging Gunicorn.
2. **Pick two devices on different networks**: Device A on campus/office Wi-Fi and Device B on a mobile hotspot (confirm different public exit IPs, e.g. via `curl https://api.ipify.org`).
3. **Trigger `429` from Device A**: send `12` consecutive anonymous `GET /api/vendors/` requests within one minute:
   - Requests `1..10` must return `200`; requests `11+` must return `429 Too Many Requests`.
4. **Verify Device B is unaffected within the same minute**: immediately send `GET /api/vendors/` from Device B:
   - **`200 OK` (PASS)**: `TRUSTED_PROXY_COUNT` isolates real client IPs per hop (`Device A` throttled independently of `Device B`).
   - **`429 Too Many Requests` (FAIL)**: `TRUSTED_PROXY_COUNT` is wrong (e.g. `0` behind a proxy, causing all requests to collapse onto the proxy's `REMOTE_ADDR`, or pointing at an internal LB hop). Adjust `TRUSTED_PROXY_COUNT` and retest.
5. **Verify `X-Forwarded-For` spoofing fails**: while Device A is still returning `429`, send `curl -i -H "X-Forwarded-For: 203.0.113.77" https://<staging-api>/api/vendors/` from Device A:
   - **`429` (PASS)**: spoofed left-most IP was ignored.
   - **`200` (FAIL)**: `TRUSTED_PROXY_COUNT` is higher than your real proxy chain or the proxy is trusting client-supplied headers without appending cleanly. Fix proxy config / count and retest.
6. **Restore normal rate**: set `THROTTLE_ANON_PER_MIN=1000` (or remove the temporary override), restart staging Gunicorn, and confirm normal traffic succeeds.

---

## 8. Scheduled `RateLimitBucket` Cleanup (`cleanup_rate_limits`)

`api_ratelimitbucket` stores both sliding-window rate-limit counters (max window `3600s`) and logout JWT revocations (`jwt_revoked_*`, lifetime read from `JWT_ACCESS_TOKEN_LIFETIME_HOURS`, default `12h`). Run `cleanup_rate_limits` daily (or hourly on high-traffic hosts) so the table stays bounded without ever purging an active token's revocation before it expires:

```bash
# Run once daily at 03:15 UTC via cron, systemd timer, or platform scheduled job
15 3 * * * cd /app/stew_backend && /app/venv/bin/python manage.py cleanup_rate_limits --batch-size 1000 --margin-seconds 3600 >> /var/log/stew-cleanup.log 2>&1
```

- Deletions execute in `1,000`-row PK batches (`order_by('key')[:batch_size]`) so PostgreSQL autovacuum/MVCC stays smooth with zero long table locks.
- Rate-limit counters older than `3600s + margin_seconds` (`2h`), revocation rows older than `JWT_ACCESS_TOKEN_LIFETIME_HOURS + margin_seconds` (`13h` at default `12h`), and `FailedLoginEvent` rows older than `FAILED_LOGIN_RETENTION_DAYS` (`30` days default) are purged.

---

## 9. Scheduled Unpaid Order Stock Expiry (`expire_unpaid_orders`)

Because creating an order reserves `Meal.left` portions before Paystack checkout completes, unpaid abandoned checkouts must expire after `UNPAID_ORDER_TTL_MINUTES` (default `30` minutes) so inventory is returned to available stock. `expire_unpaid_orders` locks each candidate order row with `SELECT ... FOR UPDATE`, re-checks payment status inside the lock (skipping paid/visible orders), marks expired unpaid orders `cancelled`, restores stock idempotently via `_restore_order_stock`, and writes an `order_expired_unpaid` audit entry. If a late Paystack webhook or verify arrives after expiry, `_mark_order_paid` routes it to `refund_pending` + `payment_received_after_cancel` audit entry without exposing the cancelled order as new kitchen work.

```bash
# Run every 5 minutes via cron, systemd timer, or platform scheduled job
*/5 * * * * cd /app/stew_backend && /app/venv/bin/python manage.py expire_unpaid_orders >> /var/log/stew-expire-orders.log 2>&1
```

---

## 10. Identity Document Purge (`purge_identity_documents`)

STEW does not collect, store, or display student IDs or any identity documents. To verify or clean any legacy identity-document references in `AuditEntry.extra` or `Compliance` records (and local `MEDIA_ROOT` files if present):

```bash
# Dry-run first (default — makes no changes, prints counts):
python manage.py purge_identity_documents

# Apply redaction/deletion after reviewing dry-run counts:
python manage.py purge_identity_documents --apply
```

---

## 11. Automatic Paystack Refunds & Retry (`retry_pending_refunds`)

- **Settings / Defaults:**
  - `FAILED_LOGIN_RETENTION_DAYS=30`, `FAILED_LOGIN_IP_HOURLY_CAP=60`
  - `CUSTOMER_CANCEL_UNTIL_PREP_STARTS=True`, `CUSTOMER_CANCEL_WINDOW_SECONDS=120`, `CUSTOMER_PAID_CANCELS_PER_DAY=5`
- **Paystack Webhook Events:** Register `https://api.<your-domain>/api/payments/webhook/` to receive `charge.success` plus all 5 refund events:
  `refund.pending`, `refund.processing`, `refund.processed`, `refund.failed`, `refund.needs_attention`.
- **Scheduled Retry Cron:** Retry stuck `refund_pending` orders (outside payout batches) every 15 minutes:
```bash
*/15 * * * * cd /app/stew_backend && /app/venv/bin/python manage.py retry_pending_refunds >> /var/log/stew-retry-refunds.log 2>&1
```
