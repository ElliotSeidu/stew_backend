# Admin Rollout Runbook (`is_platform_admin` Unification)

## Purpose
STEW unifies its definition of **platform admin** to one boolean flag:

```python
user.is_admin == True
```

Previously, endpoints and inline checks varied across `is_admin`, `is_staff`, `role == 'admin'`, `account_type == 'admin'`, and email prefix `admin@...`. After deploying the `SECURITY: unify admin definition to is_admin` change:
- `is_staff` controls Django `/admin/` access only and never grants STEW platform admin permissions.
- `role` and `account_type` describe customer/vendor workflows and never grant STEW platform admin permissions.
- Email prefixes (`admin@...`) never grant or imply STEW platform admin status.

**Important:** Run this audit BEFORE deploying the new code so legitimate STEW operators who previously relied on `is_staff`, `role='admin'`, or `account_type='admin'` do not lose access on deploy. Do not write or apply an automatic data migration for this.

---

## Step 1: Pre-Deploy Read-Only Audit Query

Connect to the production Django shell (`python manage.py shell`) and run this read-only query to find any active or inactive users who have `is_admin=False` while holding any legacy admin attribute (`is_staff=True`, `role='admin'`, `account_type='admin'`, or `email` starting with `admin@`):

```python
from django.db.models import Q
from api.models import User

candidates = (
    User.objects.filter(is_admin=False)
    .filter(
        Q(is_staff=True)
        | Q(role='admin')
        | Q(account_type='admin')
        | Q(email__istartswith='admin@')
    )
    .values('id', 'email', 'full_name', 'is_admin', 'is_staff', 'role', 'account_type', 'is_active', 'verified')
)

for row in candidates:
    print(row)
print(f"Total candidates: {len(candidates)}")
```

If `Total candidates: 0`, no user data changes are needed — proceed directly to deployment.

---

## Step 2: Review and Remediate Each Account Found

Inspect every user returned by Step 1 manually:

### Case A — Legitimate STEW Platform Admin / Operator
If the person is an authorized STEW platform administrator, explicitly grant `is_admin=True` **before deploying**:

```python
# Replace <user_id> and <operator_email> with the verified values from Step 1
User.objects.filter(id='<user_id>', email='<operator_email>').update(is_admin=True)
```

### Case B — Django `/admin/` Staff Only (`is_staff=True`) or Stale `role` / `account_type`
If the user should only have Django `/admin/` site access (`is_staff=True`) and must NOT access STEW operator APIs:
- Leave `is_admin=False`.
- Optionally normalize legacy fields that no longer confer admin rights:

```python
# Only if their role/account_type was accidentally set to 'admin'
User.objects.filter(id='<user_id>', email='<user_email>', is_admin=False).update(
    role='customer',        # or 'vendor' if they run an approved kitchen
    account_type='customer', # or 'vendor' / 'both'
)
```

### Case C — Non-Admin Account with `admin@...` Email Prefix
If a non-admin student holds an `admin@...` email address, leave `is_admin=False`. Under the unified rule they retain normal student permissions and can delete their account normally.

---

## Step 3: Post-Remediation & Post-Deploy Confirmation

Re-run the Step 1 audit query and inspect all active platform admins to confirm the exact set of platform administrators matches your team roster:

```python
from django.db.models import Q
from api.models import User

# 1. Confirm all current platform admins
admins = list(
    User.objects.filter(is_admin=True)
    .values('id', 'email', 'full_name', 'is_active', 'verified')
)
for row in admins:
    print("ADMIN:", row)

# 2. Confirm no unintended accounts still have is_admin=False with legacy admin flags
remaining = (
    User.objects.filter(is_admin=False)
    .filter(Q(is_staff=True) | Q(role='admin') | Q(account_type='admin'))
    .values('id', 'email', 'is_staff', 'role', 'account_type')
)
for row in remaining:
    print("NON-ADMIN WITH LEGACY FLAG:", row)
```

After deployment:
1. Verify each listed operator in `ADMIN:` can sign in and load `/api/admin/audit/` and `/api/admin/users/`.
2. Spot-check that any `NON-ADMIN WITH LEGACY FLAG:` user receives HTTP `403` on `/api/admin/audit/`.
