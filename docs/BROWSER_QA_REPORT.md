# STEW Pay-First & Live Browser QA Report (`rc2`)

**Date:** 2026-11-23  
**Branches:** `feature/pay-first` (branched from `rc1` / `security/rc1` in both `stew_backend` and `stew`; `main` untouched)  
**Scope:** Task A (Pay-First vendor invisibility, post-payment notification choke point, unpaid order expiry, pay-first UX) and Task B (live headless Chrome QA across journeys J1–J11, DevTools Console/Network/Application audit, PWA preview audit, and verified B5 fixes).

---

## 1. Test Environment

- **OS:** Windows + WSL2 Ubuntu (PostgreSQL 16.x on `127.0.0.1:5432`)
- **Backend:** Django + DRF (`stew_backend`), local server `http://127.0.0.1:8000`, `DEBUG=True`, `PAYSTACK_ALLOW_MOCK=True`, empty `PAYSTACK_SECRET_KEY` / `PAYSTACK_PUBLIC_KEY` (explicitly overridden from `.env` test keys so offline mock mode activates without touching Paystack)
- **Frontend:** React + Vite PWA (`stew`), dev server `http://127.0.0.1:5173` (`VITE_API_URL=http://127.0.0.1:8000/api`) and production preview `http://127.0.0.1:4173` for Service Worker / CacheStorage inspection
- **Cross-Origin Probe:** Static HTTP server on `http://127.0.0.1:5199` (excluded from `CORS_ALLOWED_ORIGINS`)
- **Browser Automation:** Google Chrome driven via `playwright-core` at desktop (`1280x800`) and mobile (`375x812`) viewports with `window.__xssTriggered` canary, console/network/response-header listeners, and HAR/JSON telemetry capture.

---

## 2. Task A1 Audit & Non-Paystack Payment Path Report

### Vendor-Visible Order Surfaces Audited & Gated (`8ee3b89`, `d8ae6b7`, `503e7dc`, `303935b`)
All vendor-facing paths now share the single server-side definition `Order.VENDOR_VISIBLE_PAYMENT_STATUSES` (`{'paid', 'released', 'refund_pending', 'refunded'}`), `Order.vendor_visible_q()`, `Order.vendor_visible()`, and `Order.is_vendor_visible` (`api/models.py`):

1. `GET /api/orders/?scope=vendor` — filtered by `Order.vendor_visible(...)`
2. `GET /api/orders/<id>/` — returns `404 {"message": "Order not found"}` when caller is the assigned vendor and `not order.is_vendor_visible`
3. `POST /api/orders/<id>/cancel/`, `/prep/`, `/complete/`, `/collection-nudge/`, `/meetup/propose/`, `/meetup/confirm/`, `/messages/` — all return `404 {"message": "Order not found"}` for the assigned vendor on unpaid/abandoned/expired orders
4. `POST /api/support/cases/` — blocks vendor attaching non-vendor-visible order (`404`)
5. `GET /api/payouts/` — server-side `held`, `released`, `weekTotal`, `newCount`, `readyCount`, `inProgressCount`, `salesByDay` computed strictly over `Order.vendor_visible(...)`; client-side fallback totals removed from `VEarnings`
6. Vendor push notifications & `AnalyticsEvent('vendor_order_placed')` — triggered strictly inside `_mark_order_paid` under `select_for_update()` guarded by `prep_at['_vendorNotifiedAt']` (stripped by `OrderSerializer.get_prepAt`); zero vendor alerts at order creation or on late payment after cancel (`refund_pending`)
7. Unpaid stock expiry — `UNPAID_ORDER_TTL_MINUTES` (default `30`), `payment.expiresAt` exposed in `OrderSerializer`, `manage.py expire_unpaid_orders` command + cron docs in `docs/PRODUCTION_PREFLIGHT.md` Section 9, plus PostgreSQL threaded concurrency test (`ExpireUnpaidOrdersConcurrencyPostgresTests`).

### Non-Paystack Payment Path Audit
- **Cash / Pay-on-Collection:** None exists in backend or frontend.
- **Manual Admin Mark-Paid:** None exists; no admin endpoint transitions `payment_status` to `paid`.
- **Dev-Only Mock Paystack Path:** Exists strictly when `DEBUG=True`, `PAYSTACK_ALLOW_MOCK=True`, and `PAYSTACK_SECRET_KEY` is empty (`api/views.py` `verify_payment_view` + `stew/src/lib/payments.js` interactive mock modal). Production startup guards refuse to boot if `PAYSTACK_ALLOW_MOCK=True` with `DEBUG=False`, and `payments.js` mock modal only activates when backend `/api/payments/initialize/` returns `mode: 'mock'`. Under the pay-first rule, mock orders remain invisible to vendors (`404`) until `/api/payments/verify/` transitions `payment_status` to `paid` via `_mark_order_paid`.

---

## 3. Live Browser QA Matrix (J1–J11 + PWA Audit)

| Journey | Scope | Result | Evidence (`docs/browser-qa/`) |
|---|---|---|---|
| **J1** | Anonymous landing (`375x812` & `1280x800`), `/legal/{terms,privacy,refunds}`, `/404`, public catalog APIs, anon `/app/discover` & `/app/vendors/v1` redirect | **PASS** (console meta error found & fixed in `09d7519`) | `qa-j1-j4-summary.json`, `j1-landing-mobile.png`, `j1-landing-desktop.png`, `j1-discover-anon-mobile.png`, `j1-discover-anon-desktop.png`, `j1-vendor-anon-mobile.png`, `j1-legal-mobile.png`, `j1-404-mobile.png` |
| **J2** | Non-campus email rejected, uppercase email normalized + OTP scraped & verified, logout clears `stew.*` & old token replay `401`, `+alias` `400`, generic wrong-password `401`, UI `429` lockout | **PASS** | `qa-j1-j4-summary.json`, `j2-account-mobile.png`, `j2-login-429-mobile.png` |
| **J3** | New student vendor application (`/app/vendor/apply/`) | **FAIL -> FIXED** (`5add793`, `8901bf9`) -> **PASS** | `qa-j1-j4-summary.json`, `j3-after-apply.png`, `qa-postfix-verify.json`, `postfix-j3-pending-banner.png` |
| **J4** | Dish CRUD, non-image `.txt`, >4 MB PNG, SVG upload, valid PNG, availability toggle off/on | **PARTIAL -> FIXED** (`7df31cb`) -> **PASS** | `qa-j1-j4-summary.json`, `j4-meal-created-desktop.png`, `qa-postfix-verify.json` |
| **J5** | One-kitchen conflict modal (`Start a new tray?`), Pay-First proof (before/after mock Paystack, auto-appearance timing, no duplicates, double verify `200`, 0 `handoffCode` leaks) | **PASS** (pre-fix `2238ms`, post-fix 6s poll `4465ms`) | `qa-j5-j7-summary.json`, `j5-pay-first-network.json`, `j5-one-kitchen-modal.png`, `j5-customer-popup.png`, `j5-vendor-before-pay.png`, `j5-vendor-after-pay.png`, `j5-customer-paid-order.png`, `qa-postfix-verify.json` |
| **J6** | Abandon payment (`mock-pay-close`) -> `Awaiting payment` -> customer cancel restores `Meal.left` (`19->18->19`); second unpaid order expired via `expire_unpaid_orders --ttl-minutes 0` (`19->18->19`); vendor sees neither | **PASS** | `qa-j5-j7-summary.json`, `j6-awaiting-payment.png` |
| **J7** | Prep stages (`shopping -> cooking -> packing -> ready`), chat, 5x+ wrong handoff code -> `429` lockout & code rotation, rotated code releases escrow, 5-star review visible on `/app/vendors/v1` | **PASS** | `qa-j5-j7-summary.json`, `j7-handoff-lockout.png`, `j7-handoff-released-vendor.png`, `j7-admin-moderation.png` |
| **J8** | Support dispute creation, admin rapid double-click on `Dismiss`, payout batch creation | **FAIL (double-click) -> FIXED** (`4976471`) -> **PASS** | `qa-j8-j11-summary.json`, `j8-support-created.png`, `j8-admin-disputes.png`, `j8-admin-payouts.png`, `qa-postfix-verify.json` |
| **J9** | Admin audit log, suspend active student via Switch toggle, active session `401` handling + token replay `401`, customer/vendor RBAC (`403` + UI redirect) | **PARTIAL (stale session on 401) -> FIXED** (`e247032`) -> **PASS** | `qa-j8-j11-summary.json`, `j9-admin-audit.png`, `j9-admin-users-suspend.png`, `j9-suspended-session-before-fix.png`, `qa-postfix-verify.json`, `postfix-j9-401-redirect.png` |
| **J10** | Stored XSS (`<img onerror>`, `"><script>`), `javascript:` URLs (`400`), Customer B / Vendor B IDOR (`403`), checkout price/qty/cross-vendor tampering, unauth `401`, cross-origin `127.0.0.1:5199` CORS block | **PASS** | `qa-j8-j11-summary.json`, `j10-xss-rendered-safe.png`, `j10-cors-probe-5199.png` |
| **J11** | Slow 3G (`5859ms`), offline mid-checkout (cart intact + online retry), Back button on mock modal (clean close, no false success), double-tap Pay now (`1` POST), offline mid-verify (no false success), expired JWT `401` | **PARTIAL (expired JWT stayed logged in) -> FIXED** (`e247032`) -> **PASS** | `qa-j8-j11-summary.json`, `j11-offline-retry.png`, `qa-postfix-verify.json` |
| **PWA** | Production build (`vite build`) + preview (`127.0.0.1:4173`): Service Worker active, valid manifest, `apiUrlsCached: []`, no hashes in `localStorage` | **PASS** | `qa-pwa-audit.json`, `pwa-preview-application.png` |

---

## 4. Findings & Remediation Table

| ID | Severity | Journey / Tab | Finding | Evidence | Resolution / Status |
|---|---|---|---|---|---|
| **QA-01** | **High** | J3 / Network & API | `/api/vendor/apply/` immediately set `active=True, open=True` (and `verify_email_view` could auto-activate inactive vendors), allowing unapproved applicants to publish meals (`201`) and appear publicly without admin approval. | `qa-j1-j4-summary.json` (`vendorActive: true`, `publishMealBeforeApprovalStatus: 201`) | **Fixed** in `stew_backend` `5add793` (`active=False, open=False`, `status='pending'`, `vendorActive`, admin auto-open on activation, removed email-verify auto-activation) and `stew` `8901bf9` (pending banner + disabled open/add controls). Verified in `qa-postfix-verify.json` (`403` before approval -> `201` after). |
| **QA-02** | **Medium** | B4 / Network Headers | Authenticated and sensitive API responses (`/api/auth/*`, `/api/orders/*`, `/api/payments/*`, `/api/payouts/*`, `/api/admin/*`, `/api/support/*`) omitted `Cache-Control: no-store, private`. | `qa-b4-devtools-summary.json` (`missingNoStoreEndpoints`: 25 endpoints with `cacheControl: null`) | **Fixed** in `stew_backend` `80b9c47` (`SecurityHeadersMiddleware` emits `Cache-Control: no-store, private` & `Pragma: no-cache`). Verified in `qa-postfix-verify.json`. |
| **QA-03** | **Medium** | J9 & J11 / Application & Network | When a user's session was suspended by admin or JWT expired (`401`), the frontend kept `stew.token`/`stew.me` in `localStorage` and remained on `/app/orders` instead of clearing state and redirecting to `/app/login`. | `qa-j8-j11-summary.json` (`studTokenStillInLs: true`, `expiredTokenClearedBeforeFix: false`) | **Fixed** in `stew` `e247032` (`stew:unauthorized` event in `api.js` handled once in `AuthProvider`, clearing `stew.*`, resetting user, toasting, redirecting via `<Protected>`). Verified in `qa-postfix-verify.json` (`remainingStewKeys: []`, `/app/login`). |
| **QA-04** | **Medium** | J8 / Network | Rapid double-clicking `Dismiss` / `Refund` in `/app/admin/disputes` fired `2` concurrent `POST /api/support/cases/<code>/resolve/` requests. | `qa-j8-j11-summary.json` (`resolvePostsFiredOnDoubleClick: 2`) | **Fixed** in `stew` `4976471` (synchronous `useRef` Set + `resolvingCode` loading/disabled state in `ADisputes`). Verified in `qa-postfix-verify.json` (`resolvePostsFiredOnDoubleClick: 1`). |
| **QA-05** | **Medium** | J4 / UI & Upload | `src/lib/upload.js` checked `file.type?.startsWith('image/')` (permitting `image/svg+xml`), and `ItemForm.pickImage` did not call `clearErrors('root')` when a valid file followed an invalid one. | `qa-j1-j4-summary.json` (`svgAlert` retained prior 4 MB error) | **Fixed** in `stew` `7df31cb` (explicit raster allowlist `image/jpeg`, `image/png`, `image/webp`, `image/gif` + `clearErrors('root')`). Verified in `qa-postfix-verify.json`. |
| **QA-06** | **Low** | B4 / Network | Order and vendor dashboards polled every `3000ms`–`5000ms` continuously, including while tabs were hidden. | `qa-b4-devtools-summary.json` | **Fixed** in `stew` `3f5ce9a` (`6000ms` interval + `document.visibilityState !== 'hidden'` guard across `Orders.jsx` and `Vendor.jsx`). Verified in `qa-postfix-verify.json` (`2` polls in `13s`). |
| **QA-07** | **Low** | J1–J11 / Console | `stew/index.html` contained `<meta http-equiv="X-Frame-Options" content="DENY" />`, which browsers ignore and log as a Console error on every page load (`206` occurrences in dev QA). | `qa-b4-devtools-summary.json` | **Fixed** in `stew` `09d7519` (removed invalid `<meta>` tag; **0** `X-Frame-Options` console errors post-fix). Clickjacking protection must be sent via HTTP headers (`X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`) at the static host/CDN layer (already documented in `PRODUCTION_PREFLIGHT.md`). |
| **QA-08** | **Info** | J1 / Routing | Unauthenticated requests to `/app/discover` and `/app/vendors/:id` redirect to `/app/login` via `<Protected roles={["customer"]}>`, while `/` (Landing), `/legal/*`, `/404`, and public catalog APIs (`/api/vendors/`, `/api/meals/`) are publicly accessible. | `qa-j1-j4-summary.json` | **Product behavior (left unchanged)** — campus-only authenticated storefront; public marketing landing lives at `/`. |

---

## 5. DevTools Console, Network & Application Summary

- **Console:** `0` uncaught `pageerror` exceptions, `0` warnings, `0` JWT/phone/PII console leaks. Pre-fix `X-Frame-Options` meta tag error (`206` entries) reduced to **`0`** after `09d7519`.
- **Network:**
  - **Security headers:** API responses emit `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=()`, and (post-`80b9c47`) `Cache-Control: no-store, private` + `Pragma: no-cache` on all authenticated/sensitive routes.
  - **Payloads & Latency:** `0` API responses exceeded `200 KB`; API calls >1s were exclusively password hashing on `/api/auth/login/` and `/api/auth/register/` (`~1.0s–1.9s`).
  - **Body Leaks:** `0` password/OTP hash fields in API JSON, `0` `handoffCode` leaks in vendor responses (`handoffCode: null`).
- **Application (PWA Preview `127.0.0.1:4173`):**
  - Service Worker `http://127.0.0.1:4173/sw.js` `activated`.
  - CacheStorage (`workbox-precache-v2-...`, 35 entries): **`apiUrlsCached: []`** (zero `/api/` responses cached).
  - `localStorage['stew.me']` contains sanitized user metadata only (no password/OTP hashes); `cookies` and `indexedDB` empty; `manifest.webmanifest` valid (`display: standalone`, 64/192/512/maskable icons).

---

## 6. J5 Pay-First Proof (Redacted Network Excerpt)

From `docs/browser-qa/j5-pay-first-network.json` (`orderId: STW-1815`):

- **Before mock Paystack confirmation (customer on Paystack popup, vendor waiting 8s + reload):**
  - `GET /api/orders/?scope=vendor` -> `200`, `orderInVendorList: false`, `vendorOrdersSample: []`
  - `GET /api/payouts/` -> `200`, `payoutHeld: 0`, `payoutNewCount: 0`
  - `GET /api/orders/STW-1815/` (as vendor) -> **`404`** `{"message": "Order not found"}`
  - `POST /api/orders/STW-1815/prep/` (as vendor) -> **`404`**
- **After mock Paystack confirmation (`mock-pay-confirm`):**
  - Appeared automatically in vendor DOM without reload in **`2238ms`** (pre-fix 3s poll) and **`4465ms`** (post-fix 6s poll on `STW-2354`).
  - `GET /api/orders/?scope=vendor` -> `orderCountMatchingId: 1` (no duplicate).
  - `GET /api/orders/STW-1815/` (as vendor) -> `200`, `handoffCode: null`, `email: null`, `payment.reference: null`, `prepAt: {"accepted": ...}` (`_vendorNotifiedAt` stripped).
  - Repeat `POST /api/payments/verify/` (as customer) -> `200` (idempotent).

---

## 7. Limitations / What Could Not Be Tested Locally

1. **Live Paystack Checkout & Public Webhook Delivery:** Tested offline using the dev-only mock Paystack modal (`PAYSTACK_ALLOW_MOCK=True`, empty `PAYSTACK_SECRET_KEY`); real Paystack HMAC-SHA512 webhook signature verification and live MoMo/card settlement are covered by Django unit tests (`api/tests_security.py`) and must be smoke-tested on staging with Paystack test keys.
2. **Real SMTP / Email & Web Push Delivery:** Local QA used Django's console email backend (`scratch/backend_qa.log`) for OTP scraping; real SMTP deliverability (SPF/DKIM/DMARC) and browser push via VAPID require staging credentials.
3. **Production CDN / TLS Headers:** `Strict-Transport-Security` (HSTS), TLS termination, and frontend static-host HTTP `X-Frame-Options: DENY` / CSP `frame-ancestors 'none'` headers must be verified against the deployed staging origin per `docs/PRODUCTION_PREFLIGHT.md`.
