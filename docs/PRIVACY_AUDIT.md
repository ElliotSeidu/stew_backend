# STEW Privacy & Identity Audit (`feature/privacy-refunds`)

**Date:** 2026-11-24  
**Baseline:** Tag `rc2` (`stew_backend` `7101e3f`, `stew` `09d7519`)  
**Scope:** Complete code, serializer, UI, notification, seed/mock, and QA evidence audit for (a) identity/compliance document collection/storage/display and (b) phone/email exposure between vendors and customers.

---

## 1. Identity & Compliance Document Audit

| Location | Current Behavior | Risk / Required Action |
|---|---|---|
| `stew/src/pages/vendor/Vendor.jsx` (`VApply`, L93, L246–255) | Renders `<Field label="Photo of your student ID">` (`input[type="file" accept="image/*,.pdf"]`, required `idDoc`) and sends `idDoc: d.idDoc?.[0]?.name` to `POST /api/vendor/apply/`. | **Remove** `idDoc` input and payload field completely. Replace with campus-email + admin verification notice. |
| `stew_backend/api/views.py` (`vendor_apply_view`, L958–1030) | Does not persist `idDoc`, but silently accepts arbitrary extra keys (`idDoc`, `id_doc`, `idPhoto`, `ghanaCard`, etc.). | **Explicitly reject** (`400`) any identity document upload/number keys (`idDoc`, `id_doc`, `idPhoto`, `id_photo`, `studentIdPhoto`, `student_id_photo`, `ghanaCard`, `ghana_card`, `idNumber`, `id_number`) so identity documents are never accepted or stored. |
| `stew_backend/api/views.py` (`admin_vendor_detail_view`, L2480–2496) & `stew/src/pages/admin/Admin.jsx` (`AVendors`) | Admin can toggle `active: True` without specifying how the chef was verified. | **Require** `verificationMethod` in `('in_person', 'video_call', 'vouched')` plus optional short `verificationNote` (max 240 chars) on activation (`active: False -> True`); refuse (`400`) activation without a valid method; write `AuditEntry` with actor, timestamp, method, and note. Never store ID numbers or images. |
| `stew_backend/api/models.py:227` (`Compliance`), `serializers.py:242` (`ComplianceSerializer`), `views.py:2239–2271`, `Admin.jsx:703` (`ACompliance`) | Stores optional FDA food-hygiene permit metadata (`type`, `number`, `issued_at`, `expires_at`, `reviewed_by`). Visible only to the owning vendor and platform admin. Does not store student ID photos. | Keep FDA permit metadata separate from identity docs; `purge_identity_documents` management command will still scan for and purge any stray identity-document fields or data URIs in `AuditEntry.extra`, `Compliance`, `Order`, `SupportCase`, `User`, and `Vendor`. |
| `stew_backend/api/management/commands/seed_data.py` | Seeds 2 sample FDA food-hygiene `Compliance` rows; no student ID images or Ghana Card numbers. | No ID images present. |
| `stew_backend/docs/browser-qa/` | Contains 32 PNG screenshots and 7 JSON summaries from `rc2` QA. **Zero** student ID photos exist (J3 QA used a synthetic 16×16 solid-cyan PNG in `scratch/pw-qa/fixtures/dish.png` that was never stored or shown in `docs/browser-qa/`). | Nothing to delete for ID photos; reported explicitly in 1.2 commit and PR notes. |
| `stew/src/pages/legal/content.js:10` | Mentions `"Files you attach, such as dispute photos or a student ID"`. | Do not rewrite legal pages directly; suggested updated copy provided in Section 3 below. |

---

## 2. Customer ↔ Vendor Phone & Email Exposure Audit

| Surface | File & Lines | Current Exposure | Required Action |
|---|---|---|---|
| **Order API (`OrderSerializer`)** | `stew_backend/api/serializers.py:117–165` | **`phone` exposed unconditionally** to vendors on `GET /api/orders/?scope=vendor`, `GET /api/orders/<id>/`, `POST /prep/`, `/complete/`, `/messages/`, `/meetup/*`, `/cancel/`, `/collection-nudge/`. (`email` is already `None` for non-owner/non-admin.) | Gate `phone` behind `_is_owner_or_admin(obj)` (return `None` to vendors, keep for owning customer and admin). Never expose vendor phone/email on `OrderSerializer`. |
| **Vendor Dashboard ("Active", "Ready", "All" tabs)** | `stew/src/pages/vendor/Vendor.jsx:940–948` | Renders `<a href="tel:${o.phone}"><Phone /> {o.phone}</a>` on every non-cancelled order card (Active, Ready, and All tabs). | **Remove** `o.phone` display and `tel:` link completely; direct vendors to the in-app chat/meetup thread inside the order modal. |
| **Vendor Order Detail Modal** | `stew/src/pages/vendor/Vendor.jsx:1100–1215` | Shows `customer`, `items`, `area`, `pickupDay`, `total`, `note`, `OrderThread`. Does not show `phone` directly, but displays unmasked `order.messages` and `order.orderNote` / `order.contactNote`. | Mask phone-like patterns in `messages`, `meetup`, `orderNote`, and `contactNote` at read time for the other party; keep unmasked for admins. |
| **Public Vendor & Meal APIs** | `stew_backend/api/serializers.py:78–114` (`VendorSerializer`, `MealSerializer`), `ReviewSerializer:222–239` | Does **not** include vendor `phone`, `email`, or `payout`. | Verified clean; add regression tests asserting no `phone`, `email`, or `payout` keys appear. |
| **Customer Order Detail & Support** | `stew/src/pages/customer/Orders.jsx`, `stew/src/pages/customer/Support.jsx` | Shows customer's own order; no vendor phone/email shown. Chat & meetup text unmasked. | Add phone-masking at read time for other party + sender notice + admin chat notice banner. |
| **Support Cases** | `stew_backend/api/serializers.py:290–302`, `views.py:2338–2379` | Only visible to the creating user and admin. `note` is unmasked. | Preserve original for admin and author; mask phone patterns if ever serialized for another non-admin party. |
| **Push & Email Notifications** | `stew_backend/api/views.py:1390–1431` (`_send_vendor_push`, `_notify_vendor_order_paid`) | Contains only `order.id`, `order.customer_name`, `order.vendor_name`, `order.total`, and line count. No customer `phone` or `email`. | Verified clean; add regression tests asserting neither phone nor email appears in push/email payloads. |
| **Analytics & Logs** | `stew_backend/api/views.py`, `stew/src/lib/analytics.js` | No phone or email written to `AnalyticsEvent` or `logger` calls on order paths. | Verified clean. |
| **Frontend `tel:` / `wa.me` / call wording** | `Vendor.jsx:942` (`tel:${o.phone}`), `config.js:151` (`CONTACT` platform support phone) | 1 `tel:` link (`Vendor.jsx:942`); 0 `wa.me` links. | Remove `Vendor.jsx:942` `tel:` link and unused `Phone` icon import. Keep STEW platform support contact in `config.js` (not customer/vendor PII). |
| **Seed / Mock Data & `docs/browser-qa/`** | `seed_data.py`, `mockData.js`, `docs/browser-qa/j5-pay-first-network.json:26` | `seed_data.py` uses fictional demo numbers (`0240000001`–`0240000003`); `mockData.js` has empty lists; `j5-pay-first-network.json:26` recorded pre-fix `"phone": "0240000001"` in the vendor response. | New Part 2 P5 evidence will prove zero phone/email leaks in live network responses. |

---

## 3. Suggested Privacy Policy Wording (Section 1.6 — Reference Only, Legal Pages Not Rewritten)

> **Identity verification (no ID documents collected):**  
> STEW verifies student identity using your `@st.knust.edu.gh` campus email address and, for student chefs, an in-person, video-call, or vouched onboarding check performed by a STEW administrator. **STEW does not collect, store, or display photos or numbers of your student ID card, Ghana Card, or any government-issued identity document.**

> **Phone number & email privacy between students and chefs:**  
> Your phone number and campus email address are never shared with chefs or other students. All order coordination takes place through STEW's in-app order chat and meetup tools, where phone-like numbers are automatically hidden from the other party.

> **Order chat review for safety and security:**  
> Messages in order chats may be reviewed by STEW administrators for safety, fraud prevention, dispute resolution, and security investigations. Every administrative review requires a documented reason and is permanently recorded in our security audit log.

> **Security & failed login retention:**  
> To protect accounts against brute-force and credential-stuffing attacks, STEW logs failed sign-in attempts—including the attempted email address, IP address, browser user agent, timestamp, and failure reason (never passwords or verification codes)—and automatically purges these records after **30 days**.
