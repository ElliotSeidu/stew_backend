# STEW Backend (Django REST Framework)

This is the complete Django backend for **STEW** — the student batch-cooking marketplace at Kwame Nkrumah University of Science and Technology (KNUST).

---

## 🔒 Security Architecture & Defensive Audit

As mandated by security policy:
1. **Strict KNUST Student Email Domain Validation**:
   - Only emails matching `^[a-zA-Z0-9._%+-]+@st\.knust\.edu\.gh$` are permitted.
   - External email services (e.g., `@gmail.com`, `@yahoo.com`, `@outlook.com`, `@hotmail.com`, or staff domains) are rejected across all endpoints (`/auth/register/`, `/auth/login/`, `/auth/login-code/request/`, `/auth/forgot-password/`, `/auth/me/`, `/orders/`).
2. **Timing-Attack Resilient Verification**:
   - Handover codes and OTP tokens are hashed before storage and compared using constant-time comparison (`secrets.compare_digest`).
3. **Escrow Invariant Enforcement**:
   - Student money is securely held upon Paystack payment verification (`payment_status = 'paid'`, `settlement_status = 'pending'`).
   - Funds are only released (`settlement_status = 'released'`) when the student explicitly marks the food collected or when the vendor verifies the student's 6-digit pickup code at handover.
4. **IDOR & Access Control**:
   - Students can only view, cancel, or message their own orders.
   - Vendors can only view and update orders placed with their kitchen.
   - Reviews can only be submitted for completed/collected orders by the student who placed the order.
   - Admin routes (`/admin/reviews/queue/`, `/payouts/batches/`) are protected by `IsAdminUser` permission classes.
5. **Rate Limiting & Brute-Force Defense**:
   - OTP verification, code logins, and registration endpoints have sliding-window rate limiters.

---

## 🚀 Setup & Execution

### 1. Activate the Virtual Environment

**Windows PowerShell:**
```powershell
cd C:\Users\ellio\Desktop\fullstack\stew_backend
.\venv\Scripts\Activate.ps1
```

**Linux/macOS:**
```bash
source venv/bin/activate
```

### 2. Environment Variables (.env)
The `.env` file in the project root holds configuration settings:
```ini
SECRET_KEY=django-insecure-stew-secret-key-knust-campus-2026-safe
DEBUG=True
ALLOWED_HOSTS=*
PAYSTACK_PUBLIC_KEY=
PAYSTACK_SECRET_KEY=
```

### 3. Run Migrations & Seed Database
```powershell
python manage.py migrate
python manage.py seed_data
```

### 4. Run the Security & API Test Suite
```powershell
python manage.py test
```

### 5. Start the Server
```powershell
python manage.py runserver 8000
```
API endpoints will be available at:
`http://localhost:8000/api/`

### 6. Frontend Build-Time Dependency (`VITE_API_URL`)
When building the companion React/Vite frontend (`stew`), `VITE_API_URL` **must** be present during `npm run build` because Vite inlines `VITE_*` environment variables at build time (and rejects missing `VITE_API_URL` at build time rather than emitting a broken 503 bundle). Example:
```powershell
$env:VITE_API_URL = 'https://api.stew.knust.edu.gh/api'
npm run build
```

---

## 🧪 Default Test Accounts
- **Student Customer**: `demo@st.knust.edu.gh` | Password: `demo1234`
- **Student Vendor**: `vendor@st.knust.edu.gh` | Password: `vendor1234`
- **Dual Vendor/Customer**: `both@st.knust.edu.gh` | Password: `both1234`
- **STEW Administrator**: `admin@st.knust.edu.gh` | Password: `admin1234`
- **Development OTP verification fallback**: `123456`
