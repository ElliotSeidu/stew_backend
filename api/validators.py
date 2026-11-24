import re
from django.conf import settings
from rest_framework.exceptions import ValidationError

KNUST_STUDENT_EMAIL_REGEX = re.compile(
    r'^[a-z0-9]+(?:[._-][a-z0-9]+)*@st\.knust\.edu\.gh\Z',
    re.IGNORECASE | re.ASCII,
)
GHANA_PHONE_REGEX = re.compile(r'^(?:\+233|0)[25]\d{8}$')
STUDENT_REF_ID_REGEX = re.compile(r'^\d{8}$')


def is_allowed_email(email: str) -> bool:
    """
    Single canonical email-eligibility check used across validators, auth views, and JWT auth.
    Allows valid @st.knust.edu.gh ASCII addresses everywhere, and exact lowercase ASCII
    addresses in BETA_EMAIL_ALLOWLIST only when APP_ENV == 'staging'.
    """
    if not email:
        return False
    normalized = str(email).strip().lower()
    if not normalized or not normalized.isascii():
        return False
    if KNUST_STUDENT_EMAIL_REGEX.match(normalized):
        return True
    if getattr(settings, 'APP_ENV', 'production') == 'staging':
        allowlist = getattr(settings, 'BETA_EMAIL_ALLOWLIST', ()) or ()
        return normalized in allowlist
    return False


def clean_knust_email(email: str) -> str:
    """
    Validates and normalizes KNUST student email addresses (or staging-allowlisted beta emails).
    """
    if not email:
        raise ValidationError({'email': 'Email is required.'})

    normalized = str(email).strip().lower()

    if not is_allowed_email(normalized):
        raise ValidationError({
            'email': 'Only valid KNUST student emails (@st.knust.edu.gh) are allowed entry. No external email services (e.g. Gmail, Yahoo, etc.) are permitted.'
        })

    return normalized


def validate_ghana_phone(phone: str) -> str:
    """Validates Ghana mobile phone numbers."""
    if not phone:
        raise ValidationError({'phone': 'Phone number is required.'})

    cleaned = re.sub(r'\s+', '', str(phone).strip())
    if not GHANA_PHONE_REGEX.match(cleaned):
        raise ValidationError({'phone': 'Enter a valid Ghana mobile number (e.g. 024XXXXXXX or +23324XXXXXXX).'})

    return cleaned


def validate_student_ref_id(ref_id: str) -> str:
    """Validates 8-digit KNUST student reference ID."""
    if not ref_id:
        raise ValidationError({'referenceId': 'Student reference ID is required.'})

    cleaned = str(ref_id).strip()
    if not STUDENT_REF_ID_REGEX.match(cleaned):
        raise ValidationError({'referenceId': 'Reference ID must be an 8-digit number.'})

    # Test/blacklisted mock ID rejected per specification
    if cleaned == '00000000':
        raise ValidationError({'referenceId': 'We could not find this reference ID in the KNUST student list.'})

    return cleaned
