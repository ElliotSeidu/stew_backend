# Browser QA Report 2 (Privacy, Refunds & Order UX — `feature/privacy-refunds`)

- **Date:** 2026-11-24
- **Environment:** Local Django dev server (`127.0.0.1:8000`, PostgreSQL 16, `PAYSTACK_ALLOW_MOCK=True`, empty `PAYSTACK_SECRET_KEY`) + Vite dev server (`127.0.0.1:5173`, `VITE_API_URL=http://127.0.0.1:8000/api`)
- **Runner:** Headless Chromium via `playwright-core` (`1280x800`)

## P1–P9 Results

| Check | Outcome | Evidence |
| --- | --- | --- |
| **P1** Vendor Apply no ID upload | **PASS** | `input[name="idDoc"]` count = `0`; notice `"STEW verifies kitchens via your campus email and an admin check. We never collect photos of student IDs or identity documents."` visible (`p1-vendor-apply-no-id.png`). |
| **P2** Admin vendor approval modal | **PASS** | Modal requires `Verification method` (`In-person check`, `Video call`, `Vouched by campus admin`) before activation (`p2-admin-vendor-approval-modal.png`). |
| **P3** Vendor sees no customer phone/email | **PASS** | `a[href^="tel:"]` count = `0`; customer phone & email absent from vendor dashboard (`p3-p8-vendor-live.png`). |
| **P4** Chat notice & Admin Conversations | **PASS** | Chat displays `"Messages in this chat may be reviewed by STEW admins for safety and security."` and masks phones to `[phone hidden]` for customer/vendor; Admin Conversations requires selecting a review reason before showing unmasked messages (`p4-admin-conversations.png`). |
| **P5** Admin Security failed-logins tab | **PASS** | Renders `Failed logins (24h)`, `Unique IPs (24h)`, `Top targeted (24h)`, and failed login rows (`p5-admin-security.png`). |
| **P6** Checkout Review & confirm step | **PASS** | Shows cancellation policy summary and confirmation checkbox before Paystack payment (`p6-checkout-review.png`). |
| **P7** Customer cancel & refund copy | **PASS** | Customer cancels paid order before prep starts; UI shows `Refunded` badge and `"up to 10 business days"` copy (`p7-customer-refund.png`). |
| **P8** Vendor cancelled tab, Received ago, no dup button | **PASS** | Live tabs exclude cancelled orders; `Cancelled` tab shows read-only cancelled order (`p8-vendor-cancelled-tab.png`); live card shows `Received ... ago`; `0` duplicate `"Order food"` buttons in `<main>`. |
| **P9** Zero console / page errors | **PASS** | `consoleErrors = []`, `pageErrors = []` across all flows. |
