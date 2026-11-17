import hmac
import hashlib
import json
import logging
import requests as http_requests
import secrets
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_UP, InvalidOperation
from django.conf import settings
from django.core.mail import send_mail
from django.db import models, transaction
from django.db.models import Avg, Count, Sum, Min, Max, Exists, OuterRef
from django.utils import timezone as dj_timezone
from django.utils.html import strip_tags
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError


def escape(value) -> str:
    """Strips HTML tags and angle brackets while preserving normal punctuation (e.g. apostrophes) for JSON responses."""
    return strip_tags(str(value or '')).replace('<', '').replace('>', '')

from api.authentication import JWTAuthentication, IsStudentUser, IsVendorUser, IsAdminUser, is_platform_admin
from api.models import (
    User, Vendor, Meal, Order, Review, Compliance,
    PayoutBatch, SupportCase, PushSubscription, AuditEntry, AnalyticsEvent
)
from api.serializers import (
    UserSerializer, RegisterSerializer, VendorSerializer,
    MealSerializer, OrderSerializer, ReviewSerializer,
    ComplianceSerializer, PayoutBatchSerializer, SupportCaseSerializer,
    AuditEntrySerializer, AdminUserSerializer
)
from api.security import (
    generate_6digit_code, hash_token, verify_hashed_token,
    generate_jwt_token, check_rate_limit
)
from api.validators import clean_knust_email, validate_student_ref_id, validate_ghana_phone

logger = logging.getLogger(__name__)


def record_audit(actor, action, entity_type, entity_id, extra=None):
    """Appends an immutable audit log entry."""
    try:
        entry_id = f"AUD-{int(dj_timezone.now().timestamp() * 1000)}-{secrets.token_hex(2)}"
        AuditEntry.objects.create(
            id=entry_id,
            actor=str(actor)[:150],
            action=str(action)[:100],
            entity_type=str(entity_type)[:64],
            entity_id=str(entity_id)[:64],
            extra=extra or {}
        )
    except Exception as e:
        logger.error(f"Audit log failure: {e}")


def _is_order_owner(user, order) -> bool:
    return bool(user and user.is_authenticated and (order.customer == user or order.email == user.email))


def _is_order_vendor(user, order) -> bool:
    return bool(user and user.is_authenticated and order.vendor and order.vendor.user == user)


def _is_order_participant(user, order) -> bool:
    return _is_order_owner(user, order) or _is_order_vendor(user, order) or is_platform_admin(user)


def _is_order_vendor_or_admin(user, order) -> bool:
    return _is_order_vendor(user, order) or is_platform_admin(user)


def _inactive_vendor_response(user, vendor):
    """Returns a 403 Response if a non-admin caller operates on a suspended or missing kitchen."""
    if is_platform_admin(user):
        return None
    if not vendor or not vendor.active:
        return Response(
            {'message': 'Your kitchen is currently suspended or inactive.'},
            status=status.HTTP_403_FORBIDDEN,
        )
    return None


def _terminal_order_response(order):
    """Returns a 400 Response if an order is already cancelled or collected."""
    if order.cancelled_at or order.collected_at or order.prep_stage == 'collected':
        return Response(
            {'message': 'This order is already completed or cancelled.'},
            status=status.HTTP_400_BAD_REQUEST,
        )
    return None


def _restore_order_stock(order) -> None:
    """Restores meal stock quantities for every item line on a cancelled order."""
    for line in order.lines or []:
        try:
            qty = int(line.get('qty') or 0)
        except (TypeError, ValueError):
            continue
        if qty > 0:
            Meal.objects.filter(id=str(line.get('mealId'))).update(left=models.F('left') + qty)


def _bound_queryset(request, queryset, default_limit: int = 200, max_limit: int = 500):
    """Slices a queryset using optional ?limit=&offset= params while keeping a hard upper bound."""
    try:
        raw_limit = int(request.query_params.get('limit', default_limit))
    except (TypeError, ValueError):
        raw_limit = default_limit
    try:
        raw_offset = int(request.query_params.get('offset', 0))
    except (TypeError, ValueError):
        raw_offset = 0
    limit = max(1, min(max_limit, raw_limit))
    offset = max(0, raw_offset)
    return queryset[offset:offset + limit]


def _sanitize_media_url(raw_val, max_len: int = 300000) -> str:
    """Allows only empty string, data:image/* URIs, or https:// / relative URLs."""
    val = str(raw_val or '').strip()
    if not val:
        return ''
    if val.startswith('data:image/') or val.startswith('https://') or val.startswith('/'):
        return val[:max_len]
    raise ValidationError('Image or logo must be a data:image/ URI or an https:// URL.')


def _safe_price(raw, field='price') -> Decimal:
    """Parses a GHS price as 2-decimal Decimal; rejects NaN/inf/negative/zero and absurd values."""
    if isinstance(raw, bool):
        raise ValidationError({field: 'Price must be a number.'})
    try:
        val = Decimal(str(raw).strip())
    except (InvalidOperation, TypeError, ValueError):
        raise ValidationError({field: 'Price must be a number.'})
    if not val.is_finite() or val < Decimal('0.50') or val > Decimal('10000.00'):
        raise ValidationError({field: 'Price must be between GH₵ 0.50 and GH₵ 10,000.'})
    return val.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)


def _safe_int(raw, lo: int, hi: int, field: str, default=None) -> int:
    if raw in (None, '') and default is not None:
        return default
    try:
        val = int(raw)
    except (TypeError, ValueError):
        raise ValidationError({field: f'{field} must be a whole number.'})
    if val < lo or val > hi:
        raise ValidationError({field: f'{field} must be between {lo} and {hi}.'})
    return val


def _unique_id(model, prefix: str, field: str = 'pk') -> str:
    """Generates a short human-friendly ID (e.g. STW-4821) guaranteed unique in the table."""
    for _ in range(20):
        candidate = f"{prefix}-{secrets.randbelow(9000) + 1000}"
        if not model.objects.filter(**{field: candidate}).exists():
            return candidate
    # Namespace is crowded: fall back to a longer random suffix
    return f"{prefix}-{secrets.token_hex(4).upper()}"


def _paystack_mock_allowed() -> bool:
    return bool(getattr(settings, 'PAYSTACK_ALLOW_MOCK', settings.DEBUG))


def _dispatch_otp_email(email: str, code: str, purpose: str) -> None:
    """Sends a 6-digit OTP email via Django's configured EMAIL_BACKEND.
    In local console development (DEBUG=True + console backend), prints a banner for local testing.
    Never logs or prints OTP codes in production.
    """
    is_dev_console = (
        getattr(settings, 'DEBUG', False)
        and getattr(settings, 'EMAIL_BACKEND', '') == 'django.core.mail.backends.console.EmailBackend'
    )
    if is_dev_console:
        banner = (
            f"\n{'=' * 64}\n"
            f"  [STEW OTP] {purpose}\n"
            f"  To:   {email}\n"
            f"  Code: {code}\n"
            f"{'=' * 64}\n"
        )
        print(banner, flush=True)
    try:
        send_mail(
            subject=f"Your STEW {purpose} code: {code}",
            message=(
                f"Hi there,\n\n"
                f"Your 6-digit STEW {purpose.lower()} code is:\n\n"
                f"    {code}\n\n"
                f"This code expires in 15 minutes. If you did not request this, you can ignore this email.\n"
            ),
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@stew.knust.edu.gh'),
            recipient_list=[email],
            fail_silently=True,
        )
    except Exception as exc:
        logger.error("Failed to dispatch OTP email to %s: %s", email, exc)



# ============================================================================
# AUTHENTICATION ENDPOINTS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    """
    Registers a new student account.
    Strictly verifies that the email is a valid KNUST student email (@st.knust.edu.gh).
    Generates a 6-digit confirmation code.
    """
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({'errors': serializer.errors, 'message': 'Invalid registration details.'}, status=status.HTTP_400_BAD_REQUEST)

    data = serializer.validated_data
    email = data['email']
    phone = data['phone']
    reference_id = data['referenceId']
    full_name = data['fullName']
    account_type = data['accountType']
    wants_vendor = account_type in ['vendor', 'both']
    kitchen_name = data.get('kitchenName', '').strip()
    sells = data.get('sells', [])
    hall = data.get('hall') or data.get('area') or ''

    # Rate limiting on registration (before DB queries to prevent email enumeration at scale)
    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    if not check_rate_limit(f"reg_{ip}", limit=10, window_seconds=600):
        return Response({'detail': 'Too many registration requests. Please try again later.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    # Check for existing user (after rate limit to prevent email enumeration at scale)
    existing_user = User.objects.filter(email=email).first()
    if existing_user and existing_user.verified:
        return Response({
            'errors': {'email': 'An account with this email already exists.'},
            'message': 'An account with this email already exists.'
        }, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(reference_id=reference_id, verified=True).exclude(email=email).exists():
        return Response({
            'errors': {'referenceId': 'This student reference ID is already registered.'},
            'message': 'This student reference ID is already registered.'
        }, status=status.HTTP_400_BAD_REQUEST)

    # Generate 6-digit verification code
    code = generate_6digit_code()
    code_hash = hash_token(code)
    expires_at = dj_timezone.now() + timedelta(minutes=15)

    with transaction.atomic():
        if existing_user and not existing_user.verified:
            user = existing_user
            user.set_password(data['password'])
            user.full_name = full_name
            user.reference_id = reference_id
            user.phone = phone
            user.hall = hall
            user.role = 'vendor' if wants_vendor else 'customer'
            user.account_type = account_type
            user.is_vendor = wants_vendor
            user.kitchen_name = kitchen_name if wants_vendor else ''
            user.sells = sells if wants_vendor else []
            user.verification_code_hash = code_hash
            user.verification_code_expires = expires_at
            user.save()
        else:
            user = User.objects.create_user(
                email=email,
                password=data['password'],
                full_name=full_name,
                reference_id=reference_id,
                phone=phone,
                hall=hall,
                role='vendor' if wants_vendor else 'customer',
                account_type=account_type,
                is_vendor=wants_vendor,
                kitchen_name=kitchen_name if wants_vendor else '',
                sells=sells if wants_vendor else [],
                verified=False,
                verification_code_hash=code_hash,
                verification_code_expires=expires_at,
            )

            # If creating a vendor, setup initial vendor record (inactive until email is verified)
            if wants_vendor and kitchen_name:
                v_id = f"v_{secrets.token_hex(4)}"
                Vendor.objects.create(
                    id=v_id,
                    user=user,
                    name=kitchen_name,
                    hall=hall,
                    open=False,
                    active=False,
                    rating=0.0,
                    reviews=0,
                    prep=6
                )

        record_audit(user.email, 'account_registered', 'user', user.id, {'accountType': account_type})

    _dispatch_otp_email(email, code, 'Email Verification')
    return Response({'email': email, 'ok': True}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@permission_classes([AllowAny])
def verify_email_view(request):
    """
    Verifies a student's email using the 6-digit code.
    Protects against brute-force attacks with strict rate limiting.
    """
    raw_email = request.data.get('email', '')
    code = str(request.data.get('code', '')).strip()

    try:
        email = clean_knust_email(raw_email)
    except ValidationError as e:
        return Response({'message': str(e.detail.get('email', e.detail))}, status=status.HTTP_400_BAD_REQUEST)

    # Brute-force protection: max 5 attempts per 10 minutes per email; burn OTP on lockout
    if not check_rate_limit(f"verify_{email}", limit=5, window_seconds=600):
        User.objects.filter(email=email).update(verification_code_hash='', verification_code_expires=None)
        return Response({'message': 'Too many failed verification attempts. Request a new code and wait 10 minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'message': 'No account found with this email.'}, status=status.HTTP_404_NOT_FOUND)

    # Constant-time hashed comparison only — no hardcoded bypass codes permitted
    code_valid = False
    if user.verification_code_hash and user.verification_code_expires and dj_timezone.now() < user.verification_code_expires:
        code_valid = verify_hashed_token(code, user.verification_code_hash)

    if not code_valid:
        return Response({'message': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

    was_unverified = not user.verified
    user.verified = True
    user.verification_code_hash = ''
    user.verification_code_expires = None
    # Bridge for frontend post-verification auto-login (Auth.jsx calls auth.loginWithCode immediately after auth.verify)
    user.login_code_hash = hash_token(code)
    user.login_code_expires = dj_timezone.now() + timedelta(minutes=2)
    user.save(update_fields=[
        'verified',
        'verification_code_hash',
        'verification_code_expires',
        'login_code_hash',
        'login_code_expires',
    ])
    if was_unverified:
        Vendor.objects.filter(user=user, active=False).update(active=True, open=True)

    token = generate_jwt_token(user)
    record_audit(user.email, 'email_verified', 'user', user.id)
    return Response({'ok': True, 'access': token, 'user': UserSerializer(user).data})


@api_view(['POST'])
@permission_classes([AllowAny])
def resend_code_view(request):
    """Resends a verification code to a KNUST student email."""
    raw_email = request.data.get('email', '')
    try:
        email = clean_knust_email(raw_email)
    except ValidationError as e:
        return Response({'message': str(e.detail.get('email', e.detail))}, status=status.HTTP_400_BAD_REQUEST)

    if not check_rate_limit(f"resend_{email}", limit=3, window_seconds=300):
        return Response({'message': 'Please wait a few minutes before requesting another code.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email)
        code = generate_6digit_code()
        user.verification_code_hash = hash_token(code)
        user.verification_code_expires = dj_timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['verification_code_hash', 'verification_code_expires'])
        _dispatch_otp_email(email, code, 'Email Verification (Resend)')
    except User.DoesNotExist:
        # Prevent email enumeration
        pass

    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([AllowAny])
def login_view(request):
    """
    Logs in a student using KNUST email and password.
    Rejects any non-student email format immediately.
    """
    raw_email = request.data.get('email', '')
    password = request.data.get('password', '')

    try:
        email = clean_knust_email(raw_email)
    except ValidationError as e:
        return Response({'message': 'Only KNUST student emails (@st.knust.edu.gh) are allowed.'}, status=status.HTTP_400_BAD_REQUEST)

    if not check_rate_limit(f"login_{email}", limit=10, window_seconds=300):
        return Response({'message': 'Too many login attempts. Please wait 5 minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'message': 'Incorrect email or password'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.check_password(password):
        return Response({'message': 'Incorrect email or password'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.verified:
        code = generate_6digit_code()
        user.verification_code_hash = hash_token(code)
        user.verification_code_expires = dj_timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['verification_code_hash', 'verification_code_expires'])
        _dispatch_otp_email(email, code, 'Email Verification')
        return Response({'code': 'unverified', 'message': 'Please verify your email first'}, status=status.HTTP_400_BAD_REQUEST)

    token = generate_jwt_token(user)
    serializer = UserSerializer(user)
    record_audit(user.email, 'login_success', 'user', user.id)
    return Response({'access': token, 'user': serializer.data})


@api_view(['POST'])
@permission_classes([AllowAny])
def request_login_code_view(request):
    """Emails a one-time 6-digit login code to a KNUST student email."""
    raw_email = request.data.get('email', '')
    try:
        email = clean_knust_email(raw_email)
    except ValidationError:
        return Response({'message': 'Only KNUST student emails (@st.knust.edu.gh) are permitted.'}, status=status.HTTP_400_BAD_REQUEST)

    if not check_rate_limit(f"login_code_req_{email}", limit=5, window_seconds=600):
        return Response({'message': 'Too many code requests. Please wait a few minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email, is_active=True, verified=True)
        code = generate_6digit_code()
        user.login_code_hash = hash_token(code)
        user.login_code_expires = dj_timezone.now() + timedelta(minutes=10)
        user.save(update_fields=['login_code_hash', 'login_code_expires'])
        _dispatch_otp_email(email, code, 'One-Time Login Code')
    except User.DoesNotExist:
        # Never reveal account presence or bypass email verification
        pass

    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([AllowAny])
def login_with_code_view(request):
    """Authenticates a student using an emailed 6-digit login code."""
    raw_email = request.data.get('email', '')
    code = str(request.data.get('code', '')).strip()

    try:
        email = clean_knust_email(raw_email)
    except ValidationError:
        return Response({'message': 'Only KNUST student emails (@st.knust.edu.gh) are permitted.'}, status=status.HTTP_400_BAD_REQUEST)

    if not check_rate_limit(f"login_code_try_{email}", limit=5, window_seconds=600):
        User.objects.filter(email=email).update(login_code_hash='', login_code_expires=None)
        return Response({'message': 'Too many failed attempts. Request a new login code after waiting 10 minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'message': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

    if not user.verified:
        return Response({'code': 'unverified', 'message': 'Please verify your email first'}, status=status.HTTP_400_BAD_REQUEST)

    code_valid = False
    if user.login_code_hash and user.login_code_expires and dj_timezone.now() < user.login_code_expires:
        code_valid = verify_hashed_token(code, user.login_code_hash)

    if not code_valid:
        return Response({'message': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

    # Invalidate code — single-use enforcement
    user.login_code_hash = ''
    user.login_code_expires = None
    user.save(update_fields=['login_code_hash', 'login_code_expires'])

    token = generate_jwt_token(user)
    serializer = UserSerializer(user)
    record_audit(user.email, 'login_code_success', 'user', user.id)
    return Response({'access': token, 'user': serializer.data})


@api_view(['POST'])
@permission_classes([AllowAny])
def forgot_password_view(request):
    """Initiates a password reset by sending a reset code."""
    raw_email = request.data.get('email', '')
    try:
        email = clean_knust_email(raw_email)
    except ValidationError:
        return Response({'message': 'Only KNUST student emails (@st.knust.edu.gh) are permitted.'}, status=status.HTTP_400_BAD_REQUEST)

    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    if not check_rate_limit(f"forgot_{email}", limit=5, window_seconds=600) or not check_rate_limit(f"forgot_ip_{ip}", limit=15, window_seconds=600):
        return Response({'message': 'Too many password reset requests. Please wait a few minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    try:
        user = User.objects.get(email=email)
        code = generate_6digit_code()
        user.reset_code_hash = hash_token(code)
        user.reset_code_expires = dj_timezone.now() + timedelta(minutes=15)
        user.save(update_fields=['reset_code_hash', 'reset_code_expires'])
        _dispatch_otp_email(email, code, 'Password Reset Code')
    except User.DoesNotExist:
        pass

    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password_view(request):
    """Resets password after verifying the 6-digit reset code."""
    raw_email = request.data.get('email', '')
    code = str(request.data.get('code', '')).strip()
    new_password = request.data.get('password', '')

    try:
        email = clean_knust_email(raw_email)
    except ValidationError:
        return Response({'message': 'Invalid KNUST student email.'}, status=status.HTTP_400_BAD_REQUEST)

    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    if not check_rate_limit(f"reset_try_{email}", limit=5, window_seconds=600) or not check_rate_limit(f"reset_ip_{ip}", limit=15, window_seconds=600):
        User.objects.filter(email=email).update(reset_code_hash='', reset_code_expires=None)
        return Response({'message': 'Too many reset attempts. Request a new code after waiting 10 minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    if len(new_password) < 8 or not any(c.isalpha() for c in new_password) or not any(c.isdigit() for c in new_password):
        return Response({'errors': {'password': 'Password must be at least 8 characters and contain letters and numbers.'}}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'message': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

    code_valid = False
    if user.reset_code_hash and user.reset_code_expires and dj_timezone.now() < user.reset_code_expires:
        code_valid = verify_hashed_token(code, user.reset_code_hash)

    if not code_valid:
        return Response({'message': 'Invalid or expired code'}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.reset_code_hash = ''
    user.reset_code_expires = None
    user.save(update_fields=['password', 'reset_code_hash', 'reset_code_expires'])

    record_audit(user.email, 'password_reset_success', 'user', user.id)
    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([AllowAny])
def check_reference_view(request):
    """Verifies that a student reference ID exists on KNUST records."""
    ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    if not check_rate_limit(f"check_ref_{ip}", limit=30, window_seconds=60):
        return Response({'detail': 'Too many requests. Please slow down.', 'message': 'Too many requests. Please slow down.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    ref_id = request.data.get('referenceId', '')
    try:
        validate_student_ref_id(ref_id)
        return Response({'ok': True})
    except ValidationError as e:
        status_code = status.HTTP_404_NOT_FOUND if str(ref_id).strip() == '00000000' else status.HTTP_400_BAD_REQUEST
        msg = e.detail.get('referenceId', e.detail) if isinstance(e.detail, dict) else e.detail
        return Response({'detail': msg, 'message': msg}, status=status_code)


@api_view(['GET', 'PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def me_view(request):
    """Retrieves or updates current student profile."""
    user = request.user
    if request.method == 'GET':
        return Response(UserSerializer(user).data)

    data = request.data
    # Email is the verified identity of the account and drives order ownership.
    # It can never be changed via profile PATCH (would allow claiming an unverified address).
    if 'email' in data:
        new_email = clean_knust_email(data['email'])
        if new_email != user.email:
            return Response({'errors': {'email': 'Your KNUST email cannot be changed here. Contact support.'}}, status=status.HTTP_400_BAD_REQUEST)

    changed_fields = []
    if 'fullName' in data:
        name = escape(str(data['fullName']).strip())[:150]
        if len(name) < 3:
            return Response({'errors': {'fullName': 'Enter your full name.'}}, status=status.HTTP_400_BAD_REQUEST)
        user.full_name = name
        changed_fields.append('full_name')
    if 'area' in data or 'hall' in data:
        user.hall = escape(str(data.get('area') or data.get('hall') or '').strip())[:100]
        changed_fields.append('hall')
    if 'phone' in data:
        user.phone = validate_ghana_phone(data['phone'])
        changed_fields.append('phone')
    if 'kitchenName' in data:
        user.kitchen_name = escape(str(data['kitchenName']).strip())[:150]
        changed_fields.append('kitchen_name')
    if 'sells' in data and isinstance(data['sells'], list):
        user.sells = [escape(str(s).strip())[:60] for s in data['sells'][:20] if str(s).strip()]
        changed_fields.append('sells')
    if 'bio' in data:
        user.bio = escape(str(data['bio']).strip()[:500])
        changed_fields.append('bio')
    if 'prep' in data:
        try:
            prep_val = int(data['prep'])
            if not (1 <= prep_val <= 240):
                return Response({'errors': {'prep': 'Prep time must be between 1 and 240.'}}, status=status.HTTP_400_BAD_REQUEST)
            user.prep = prep_val
            changed_fields.append('prep')
        except (ValueError, TypeError):
            return Response({'errors': {'prep': 'Prep time must be a number.'}}, status=status.HTTP_400_BAD_REQUEST)
    if 'payout' in data:
        user.payout = validate_ghana_phone(data['payout'])
        changed_fields.append('payout')
    if 'logo' in data:
        try:
            user.logo = _sanitize_media_url(data.get('logo'), max_len=300000)
            changed_fields.append('logo')
        except ValidationError as e:
            return Response({'errors': {'logo': str(e.detail[0] if isinstance(e.detail, list) else e.detail)}}, status=status.HTTP_400_BAD_REQUEST)

    if changed_fields:
        user.save(update_fields=changed_fields + ['updated_at'])

    # Keep Vendor record synchronized when a vendor updates their kitchen profile
    if user.is_vendor or user.role == 'vendor' or user.account_type in ('vendor', 'both'):
        vendor = Vendor.objects.filter(user=user).first()
        if vendor:
            if user.kitchen_name:
                vendor.name = user.kitchen_name
            if user.hall:
                vendor.hall = user.hall
            vendor.bio = user.bio
            vendor.prep = user.prep
            vendor.logo = user.logo
            if vendor.active and ('open' in data or 'kitchenOpen' in data):
                raw_open = data.get('open', data.get('kitchenOpen'))
                vendor.open = raw_open is True or str(raw_open).lower() in ('true', '1')
            vendor.save()

    record_audit(user.email, 'profile_updated', 'user', user.id)
    return Response(UserSerializer(user).data)


@api_view(['DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def delete_account_view(request):
    """Permanently deletes student or vendor account (admin cannot be deleted)."""
    user = request.user
    if is_platform_admin(user):
        return Response({'message': 'Admin accounts cannot be deleted.'}, status=status.HTTP_400_BAD_REQUEST)

    user_email = user.email
    user_id = user.id
    with transaction.atomic():
        # Soft delete or delete records
        Vendor.objects.filter(user=user).delete()
        user.delete()
        record_audit(user_email, 'account_deleted', 'user', user_id)

    return Response({'ok': True})


# ============================================================================
# VENDORS & MEALS
# ============================================================================

@api_view(['GET'])
@permission_classes([AllowAny])
def vendors_list_view(request):
    """Lists all active student kitchen vendors."""
    vendors = _bound_queryset(request, Vendor.objects.filter(active=True))
    return Response(VendorSerializer(vendors, many=True).data)


@api_view(['GET'])
@permission_classes([AllowAny])
def vendor_detail_view(request, pk):
    """Retrieves vendor details."""
    try:
        vendor = Vendor.objects.get(id=pk)
    except Vendor.DoesNotExist:
        return Response({'message': 'Kitchen not found'}, status=status.HTTP_404_NOT_FOUND)
    if not vendor.active:
        allow_inactive = False
        try:
            auth_res = JWTAuthentication().authenticate(request)
            if auth_res and is_platform_admin(auth_res[0]):
                allow_inactive = True
        except Exception:
            allow_inactive = False
        if not allow_inactive:
            return Response({'message': 'Kitchen not found'}, status=status.HTTP_404_NOT_FOUND)
    return Response(VendorSerializer(vendor).data)


@api_view(['GET', 'POST'])
@permission_classes([AllowAny])
def meals_list_view(request):
    """Lists available meals, or allows vendor to add a new dish."""
    if request.method == 'GET':
        if request.query_params.get('mine') == 'true':
            auth_res = JWTAuthentication().authenticate(request)
            if not auth_res:
                return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
            user, _ = auth_res
            meals = _bound_queryset(
                request,
                Meal.objects.select_related('vendor').filter(vendor__user=user).order_by('-created_at'),
            )
            return Response(MealSerializer(meals, many=True).data)
        meals = _bound_queryset(request, Meal.objects.select_related('vendor').filter(on=True, vendor__active=True))
        return Response(MealSerializer(meals, many=True).data)

    # Adding a meal requires verified, active vendor authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

    jwt_auth = JWTAuthentication()
    auth_res = jwt_auth.authenticate(request)
    if not auth_res:
        return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
    user, _ = auth_res
    if not user.verified:
        return Response({'message': 'Please verify your email first.'}, status=status.HTTP_403_FORBIDDEN)
    if not (user.is_vendor or user.role == 'vendor' or user.account_type in ('vendor', 'both') or is_platform_admin(user)):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

    vendor = Vendor.objects.filter(user=user).first()
    if not vendor:
        return Response({'message': 'Vendor profile not found for this account.'}, status=status.HTTP_400_BAD_REQUEST)
    blocked = _inactive_vendor_response(user, vendor)
    if blocked:
        return blocked

    data = request.data
    name = escape(str(data.get('name', '')).strip())[:150]
    if len(name) < 2:
        return Response({'errors': {'name': 'Give the dish a name.'}}, status=status.HTTP_400_BAD_REQUEST)
    try:
        price = _safe_price(data.get('price'))
        left = _safe_int(data.get('stock') if data.get('stock') not in (None, '') else data.get('left'), 0, 9999, 'stock', default=10)
        image = _sanitize_media_url(data.get('image'), max_len=300000)
    except ValidationError as e:
        return Response({'errors': e.detail, 'message': 'Please check the dish details.'}, status=status.HTTP_400_BAD_REQUEST)

    meal_id = f"m_{secrets.token_hex(4)}"
    meal = Meal.objects.create(
        id=meal_id,
        vendor=vendor,
        name=name,
        desc=escape(str(data.get('desc', '')).strip())[:1000],
        price=price,
        cat=escape(str(data.get('cat', 'Soups')))[:64],
        left=left,
        image=image,
        on=True
    )
    record_audit(user.email, 'meal_created', 'meal', meal.id, {'name': meal.name})
    return Response(MealSerializer(meal).data, status=status.HTTP_201_CREATED)


@api_view(['PATCH', 'DELETE'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def meal_detail_view(request, pk):
    """Edits or deletes a dish on the vendor's menu."""
    try:
        meal = Meal.objects.get(id=pk)
    except Meal.DoesNotExist:
        return Response({'message': 'Meal not found'}, status=status.HTTP_404_NOT_FOUND)

    # Permission check: must belong to user's vendor unless admin
    if not is_platform_admin(request.user) and meal.vendor.user != request.user:
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    blocked = _inactive_vendor_response(request.user, meal.vendor)
    if blocked:
        return blocked

    if request.method == 'DELETE':
        meal.delete()
        record_audit(request.user.email, 'meal_deleted', 'meal', pk)
        return Response({'ok': True})

    data = request.data
    try:
        if 'name' in data:
            name = escape(str(data['name']).strip())[:150]
            if len(name) < 2:
                raise ValidationError({'name': 'Give the dish a name.'})
            meal.name = name
        if 'price' in data:
            meal.price = _safe_price(data['price'])
        if 'stock' in data or 'left' in data:
            meal.left = _safe_int(data.get('stock', data.get('left')), 0, 9999, 'stock')
        if 'desc' in data:
            meal.desc = escape(str(data['desc']).strip())[:1000]
        if 'cat' in data:
            meal.cat = escape(str(data['cat']))[:64]
        if 'on' in data:
            meal.on = data['on'] is True or str(data['on']).lower() in ('true', '1')
        if 'image' in data:
            meal.image = _sanitize_media_url(data['image'], max_len=300000)
    except ValidationError as e:
        return Response({'errors': e.detail, 'message': 'Please check the dish details.'}, status=status.HTTP_400_BAD_REQUEST)

    meal.save()
    record_audit(request.user.email, 'meal_updated', 'meal', pk)
    return Response(MealSerializer(meal).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def vendor_apply_view(request):
    """Submits vendor onboarding application."""
    user = request.user
    if not check_rate_limit(f"vendor_apply_{user.id}", limit=5, window_seconds=300):
        return Response({'message': 'Too many kitchen applications. Please wait a few minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    data = request.data
    kitchen_name = escape(str(data.get('kitchen') or data.get('kitchenName') or '').strip())[:150]
    if len(kitchen_name) < 2:
        return Response({'errors': {'kitchen': 'Give your kitchen a name.'}}, status=status.HTTP_400_BAD_REQUEST)
    hall = escape(str(data.get('hall') or data.get('area') or user.hall).strip())[:100]
    sells = data.get('sells', [])
    if isinstance(sells, str):
        sells = [escape(s.strip())[:60] for s in sells.split(',') if s.strip()][:20]
    elif isinstance(sells, list):
        sells = [escape(str(s).strip())[:60] for s in sells if str(s).strip()][:20]
    else:
        sells = []

    existing_vendor = Vendor.objects.filter(user=user).first()
    if existing_vendor and not existing_vendor.active:
        return Response(
            {'message': 'Your kitchen is currently suspended and cannot be reactivated without admin approval.'},
            status=status.HTTP_403_FORBIDDEN,
        )

    with transaction.atomic():
        user.kitchen_name = kitchen_name
        user.hall = hall
        user.sells = sells
        user.is_vendor = True
        user.role = 'vendor' if not is_platform_admin(user) else user.role
        user.account_type = 'both' if user.account_type == 'customer' else user.account_type
        if 'payout' in data:
            user.payout = validate_ghana_phone(data['payout'])
        if 'about' in data:
            user.bio = escape(str(data['about']).strip()[:500])
        if 'logo' in data:
            try:
                user.logo = _sanitize_media_url(data['logo'], max_len=300000)
            except ValidationError as e:
                return Response({'errors': {'logo': str(e.detail[0] if isinstance(e.detail, list) else e.detail)}}, status=status.HTTP_400_BAD_REQUEST)
        user.save()

        # Update or create vendor profile
        vendor, _ = Vendor.objects.get_or_create(
            user=user,
            defaults={
                'id': f"v_{secrets.token_hex(4)}",
                'name': kitchen_name,
                'hall': hall,
                'bio': user.bio,
                'logo': user.logo,
                'prep': user.prep,
                'rating': 0.0,
                'reviews': 0,
                'open': True,
                'active': True,
            }
        )
        vendor.name = kitchen_name
        vendor.hall = hall
        vendor.bio = user.bio
        if user.logo:
            vendor.logo = user.logo
        vendor.prep = user.prep
        vendor.open = True
        vendor.active = True
        vendor.save()

        record_audit(user.email, 'vendor_applied', 'vendor', vendor.id)

    return Response({'status': 'active', 'ok': True, 'user': UserSerializer(user).data})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def vendor_activate_view(request):
    """Marks user as an active vendor."""
    user = request.user
    user.is_vendor = True
    if not is_platform_admin(user):
        user.role = 'vendor'
    if user.account_type == 'customer':
        user.account_type = 'both'
    user.save()
    return Response(UserSerializer(user).data)


# ============================================================================
# ORDERS & ESCROW LIFECYCLE
# ============================================================================

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def orders_view(request):
    """Creates a new order, or lists orders for the user/vendor/admin."""
    user = request.user

    if request.method == 'GET':
        scope = request.query_params.get('scope', '').strip().lower()
        if is_platform_admin(user):
            orders = Order.objects.select_related('vendor', 'customer').all().order_by('-created_at')
        elif scope == 'vendor' and (user.is_vendor or user.role in ['vendor', 'both']):
            orders = Order.objects.select_related('vendor', 'customer').filter(vendor__user=user).order_by('-created_at')
        elif scope == 'customer':
            orders = Order.objects.select_related('vendor', 'customer').filter(
                models.Q(customer=user) | models.Q(email=user.email)
            ).order_by('-created_at')
        elif user.is_vendor or user.role in ['vendor', 'both']:
            # Vendors see both orders for their kitchen and personal customer orders
            orders = Order.objects.select_related('vendor', 'customer').filter(
                models.Q(vendor__user=user) | models.Q(customer=user) | models.Q(email=user.email)
            ).distinct().order_by('-created_at')
        else:
            orders = Order.objects.select_related('vendor', 'customer').filter(
                models.Q(customer=user) | models.Q(email=user.email)
            ).order_by('-created_at')
        # Annotate whether each order has a review to avoid N+1 queries in OrderSerializer.get_reviewed
        orders = orders.annotate(_has_review=Exists(Review.objects.filter(order_id=OuterRef('pk'))))
        orders = _bound_queryset(request, orders)
        return Response(OrderSerializer(orders, many=True, context={'request': request}).data)

    # POST: Place order
    if not check_rate_limit(f"order_create_{user.id}", limit=20, window_seconds=60):
        return Response({'message': 'Too many orders placed too quickly. Please wait a moment.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    data = request.data

    # --- Validate order lines schema ----------------------------------------
    raw_lines = data.get('lines', [])
    if not isinstance(raw_lines, list) or len(raw_lines) == 0:
        return Response({'errors': {'lines': 'Order must contain at least one item.'}}, status=status.HTTP_400_BAD_REQUEST)
    MAX_LINES = 20
    if len(raw_lines) > MAX_LINES:
        return Response({'errors': {'lines': f'An order cannot contain more than {MAX_LINES} items.'}}, status=status.HTTP_400_BAD_REQUEST)

    validated_lines = []
    requested_qty = {}
    line_vendor = None
    for idx, line in enumerate(raw_lines):
        if not isinstance(line, dict):
            return Response({'errors': {'lines': f'Item at position {idx + 1} is malformed.'}}, status=status.HTTP_400_BAD_REQUEST)
        if 'mealId' not in line or 'qty' not in line:
            return Response({'errors': {'lines': f'Item at position {idx + 1} is missing mealId or qty.'}}, status=status.HTTP_400_BAD_REQUEST)
        try:
            qty = int(line['qty'])
        except (ValueError, TypeError):
            return Response({'errors': {'lines': f'Item at position {idx + 1} has an invalid quantity.'}}, status=status.HTTP_400_BAD_REQUEST)
        if qty < 1 or qty > 50:
            return Response({'errors': {'lines': f'Item at position {idx + 1} has an invalid quantity.'}}, status=status.HTTP_400_BAD_REQUEST)
        meal_id_str = str(line['mealId'])[:64]
        # Authoritative lookup: price, name and vendor ALWAYS come from the database.
        # Unknown meals are rejected so a client can never supply its own price.
        db_meal = Meal.objects.select_related('vendor').filter(id=meal_id_str).first()
        if not db_meal or not db_meal.on or not db_meal.vendor.active:
            return Response({'errors': {'lines': f'"{escape(str(line.get("name", "This dish")))[:60]}" is no longer available.'}}, status=status.HTTP_400_BAD_REQUEST)
        if line_vendor is None:
            line_vendor = db_meal.vendor
        elif db_meal.vendor_id != line_vendor.id:
            return Response({'errors': {'lines': 'A tray can only contain food from one kitchen.'}}, status=status.HTTP_400_BAD_REQUEST)
        line_price = Decimal(str(db_meal.price)).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        requested_qty[db_meal.id] = requested_qty.get(db_meal.id, 0) + qty
        validated_lines.append({
            'mealId': db_meal.id,
            'name': db_meal.name,
            'price': float(line_price),
            'qty': qty,
            'note': escape(str(line.get('note', '') or '').strip())[:200],
            'image': db_meal.image[:300] if db_meal.image.startswith(('https://', '/')) else '',
        })
    # ------------------------------------------------------------------------

    vendor = line_vendor
    if not vendor.open:
        return Response({'message': f'{vendor.name} is not taking orders right now.'}, status=status.HTTP_400_BAD_REQUEST)
    if vendor.user_id and vendor.user_id == user.id:
        return Response({'message': 'You cannot order from your own kitchen.'}, status=status.HTTP_400_BAD_REQUEST)

    # Recalculate subtotal from server-validated lines using exact Decimal math
    subtotal = sum(
        (Decimal(str(line['price'])) * Decimal(line['qty']) for line in validated_lines),
        Decimal('0.00'),
    ).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    fee = (subtotal * Decimal('0.05')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
    total = (subtotal + fee).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    # The order always belongs to the authenticated account's verified email —
    # never a client-supplied address (that would grant another student access to it).
    order_email = user.email
    phone = validate_ghana_phone(data.get('phone') or user.phone)
    vendor_name = vendor.name

    # Cryptographically random 6-digit pickup handover verification code
    handoff_code = generate_6digit_code()
    now_ms = int(dj_timezone.now().timestamp() * 1000)

    with transaction.atomic():
        # Lock meals and enforce stock so two students cannot buy the last portion
        locked = {m.id: m for m in Meal.objects.select_for_update().filter(id__in=list(requested_qty.keys()))}
        for meal_id, want in requested_qty.items():
            m = locked.get(meal_id)
            if m is None or m.left < want:
                left = m.left if m else 0
                return Response({'errors': {'lines': f'Only {left} portion(s) of "{m.name if m else "a dish"}" left.'}}, status=status.HTTP_400_BAD_REQUEST)
        for meal_id, want in requested_qty.items():
            Meal.objects.filter(id=meal_id).update(left=models.F('left') - want)

        order_id = _unique_id(Order, 'STW')
        order = Order.objects.create(
            id=order_id,
            customer=user,
            customer_name=escape(str(user.full_name or user.email.split('@')[0]))[:150],
            email=order_email,
            phone=phone,
            area=escape(str(data.get('area') or user.hall or 'Campus'))[:100],
            contact_note=escape(str(data.get('contactNote', '') or ''))[:200],
            vendor=vendor,
            vendor_name=vendor_name,
            lines=validated_lines,
            subtotal=subtotal,
            fee=fee,
            total=total,
            order_note=escape(str(data.get('orderNote', '') or ''))[:500],
            handoff_code=handoff_code,
            pickup_day=escape(str(data.get('pickupDay', '') or ''))[:32],
            pickup_slot=escape(str(data.get('pickupSlot', '') or 'afternoon'))[:32],
            prep_stage='accepted',
            prep_at={'accepted': now_ms},
            payment_status='pending',
            payment_provider='paystack',
            settlement_status='pending',
            messages=[]
        )
        record_audit(user.email, 'order_created', 'order', order.id, {'total': float(total), 'vendor': vendor_name})

    return Response(OrderSerializer(order, context={'request': request}).data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def order_detail_view(request, pk):
    """
    Retrieves full details for a single order.
    Protected against IDOR: Only customer, assigned vendor, or admin can access.
    """
    try:
        order = Order.objects.select_related('vendor', 'customer').get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    user = request.user
    is_owner = (order.customer == user or order.email == user.email)
    is_order_vendor = (order.vendor and order.vendor.user == user)
    if not (is_owner or is_order_vendor or is_platform_admin(user)):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def cancel_order_view(request, pk):
    """
    Cancels an order within the cancellation window (120 seconds, before prep starts).
    Enforces escrow refund states under row lock.
    """
    user = request.user
    with transaction.atomic():
        try:
            order = Order.objects.select_for_update().select_related('vendor').get(id=pk)
        except Order.DoesNotExist:
            return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        is_owner = (order.customer == user or order.email == user.email)
        is_order_vendor = (order.vendor and order.vendor.user == user)
        if not (is_owner or is_order_vendor or is_platform_admin(user)):
            return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        if order.cancelled_at:
            return Response({'message': 'This order is already cancelled.'}, status=status.HTTP_400_BAD_REQUEST)
        if order.collected_at or order.prep_stage == 'collected':
            return Response({'message': 'This order was already handed over and cannot be cancelled. Open a support case instead.'}, status=status.HTTP_400_BAD_REQUEST)

        # If student, enforce time window and prep stage
        if is_owner and not (is_platform_admin(user) or is_order_vendor):
            if order.prep_stage != 'accepted':
                return Response({'message': 'The kitchen has already started on this order.'}, status=status.HTTP_400_BAD_REQUEST)
            elapsed_seconds = (dj_timezone.now() - order.created_at).total_seconds()
            if elapsed_seconds > 120:
                return Response({'message': 'This order can no longer be cancelled (120s limit passed).'}, status=status.HTTP_400_BAD_REQUEST)

        order.cancelled_at = dj_timezone.now()
        was_paid = order.payment_status in ['paid', 'released']
        if was_paid and order.settlement_status == 'released':
            order.payment_status = 'refund_pending'
        elif was_paid:
            order.payment_status = 'refunded'
        else:
            order.payment_status = 'cancelled'

        order.save(update_fields=['cancelled_at', 'payment_status'])
        _restore_order_stock(order)
        record_audit(user.email, 'order_cancelled', 'order', order.id, {'status': 'cancelled'})

    return Response(OrderSerializer(order, context={'request': request}).data)


# ============================================================================
# PAYSTACK & ESCROW PAYMENTS
# ============================================================================

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def init_payment_view(request):
    """Initializes Paystack payment for an order."""
    if not check_rate_limit(f"pay_init_{request.user.id}", limit=15, window_seconds=60):
        return Response({'message': 'Too many payment attempts. Please wait a moment.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    order_id = request.data.get('orderId')
    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # IDOR defense: only the order's customer or an admin can initialize payment
    if not (_is_order_owner(request.user, order) or is_platform_admin(request.user)):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

    if order.cancelled_at:
        return Response({'message': 'This order was cancelled'}, status=status.HTTP_400_BAD_REQUEST)

    if order.payment_status in ['paid', 'released']:
        return Response({'message': 'This order is already paid'}, status=status.HTTP_400_BAD_REQUEST)
    if order.payment_status in ['refunded', 'refund_pending', 'cancelled']:
        return Response({'message': 'This order can no longer be paid for'}, status=status.HTTP_400_BAD_REQUEST)

    reference = f"PSK-{secrets.token_hex(8).upper()}"
    amount_pesewas = int((Decimal(str(order.total)) * Decimal('100')).to_integral_value(rounding=ROUND_HALF_UP))
    public_key = getattr(settings, 'PAYSTACK_PUBLIC_KEY', '')
    secret_key = getattr(settings, 'PAYSTACK_SECRET_KEY', '')

    if secret_key:
        try:
            ps_resp = http_requests.post(
                'https://api.paystack.co/transaction/initialize',
                headers={'Authorization': f'Bearer {secret_key}', 'Content-Type': 'application/json'},
                json={
                    'email': order.email,
                    'amount': amount_pesewas,
                    'currency': 'GHS',
                    'reference': reference,
                    'channels': ['mobile_money', 'card'],
                    'metadata': {'orderId': order.id},
                },
                timeout=10,
            )
            ps_data = ps_resp.json()
        except (http_requests.RequestException, ValueError) as exc:
            logger.error("Paystack initialize failed: %s", exc)
            return Response({'message': 'Payment gateway unavailable. Please retry.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        if not ps_resp.ok or not ps_data.get('status'):
            logger.warning("Paystack initialize rejected for order %s: %s", order.id, ps_data.get('message'))
            return Response({'message': 'The payment could not be started. Please try again.'}, status=status.HTTP_502_BAD_GATEWAY)
        order.payment_reference = reference
        order.save(update_fields=['payment_reference'])
        ps = ps_data.get('data') or {}
        return Response({
            'reference': reference,
            'amount': amount_pesewas,
            'currency': 'GHS',
            'publicKey': public_key,
            'email': order.email,
            'access_code': ps.get('access_code'),
            'checkout_url': ps.get('authorization_url'),
        })

    if not _paystack_mock_allowed():
        logger.error("PAYSTACK_SECRET_KEY is not configured; refusing to take payments.")
        return Response({'message': 'Payments are not configured yet. Please contact support.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    # Development-only simulated payment (never enabled when DEBUG=False unless explicitly opted in)
    order.payment_reference = reference
    order.save(update_fields=['payment_reference'])
    return Response({
        'reference': reference,
        'amount': amount_pesewas,
        'currency': 'GHS',
        'publicKey': public_key,
        'email': order.email,
        'mock': True,
    })


def _mark_order_paid(order, actor, reference):
    """Idempotently moves an order into escrow-held 'paid' state."""
    with transaction.atomic():
        locked = Order.objects.select_for_update().get(pk=order.pk)
        if locked.payment_status in ['paid', 'released']:
            return locked
        locked.payment_status = 'paid'
        locked.paid_at = dj_timezone.now()
        locked.settlement_status = 'pending'  # Escrow held until student confirms collection
        locked.save(update_fields=['payment_status', 'paid_at', 'settlement_status'])
        record_audit(actor, 'payment_verified', 'order', locked.id, {'reference': reference})
        return locked


def _paystack_verify(reference, order):
    """Returns (ok, http_status, message) after verifying a transaction with Paystack."""
    secret_key = getattr(settings, 'PAYSTACK_SECRET_KEY', '')
    try:
        ps_resp = http_requests.get(
            f"https://api.paystack.co/transaction/verify/{reference}",
            headers={'Authorization': f'Bearer {secret_key}'},
            timeout=10,
        )
        ps_data = ps_resp.json()
    except (http_requests.RequestException, ValueError) as exc:
        logger.error("Paystack API call failed: %s", exc)
        return False, status.HTTP_503_SERVICE_UNAVAILABLE, 'Payment gateway unavailable. Please retry.'
    tx = ps_data.get('data') or {}
    if not ps_resp.ok or tx.get('status') != 'success':
        logger.warning("Paystack verification failed for ref=%s: %s", reference, ps_data.get('message'))
        return False, status.HTTP_402_PAYMENT_REQUIRED, 'Payment could not be verified. Please try again.'
    if tx.get('reference') != reference or str(tx.get('currency', 'GHS')).upper() != 'GHS':
        return False, status.HTTP_402_PAYMENT_REQUIRED, 'Payment details do not match this order.'
    # Validate amount to prevent partial-payment attacks
    expected_pesewas = int((Decimal(str(order.total)) * Decimal('100')).to_integral_value(rounding=ROUND_HALF_UP))
    if int(tx.get('amount') or 0) < expected_pesewas:
        logger.warning("Payment amount mismatch for order %s (ref=%s)", order.id, reference)
        return False, status.HTTP_402_PAYMENT_REQUIRED, 'Payment amount does not match order total.'
    return True, status.HTTP_200_OK, ''


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def verify_payment_view(request):
    """
    Verifies payment with Paystack and updates order escrow state.
    Calls the Paystack /transaction/verify/:reference endpoint with the SECRET key
    before marking the order as paid. Payment becomes 'paid' and money is HELD by
    STEW pending student collection (escrow).
    """
    if not check_rate_limit(f"pay_verify_{request.user.id}", limit=30, window_seconds=60):
        return Response({'message': 'Too many payment verification checks. Please wait a moment.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    order_id = request.data.get('orderId')
    reference = str(request.data.get('reference', '')).strip()

    if not order_id or not reference:
        return Response({'message': 'orderId and reference are required.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        order = Order.objects.get(id=order_id)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    # IDOR: only the order owner may verify their own payment
    user = request.user
    if not (_is_order_owner(user, order) or is_platform_admin(user)):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

    if order.payment_status in ['paid', 'released']:
        return Response(OrderSerializer(order, context={'request': request}).data)

    if order.cancelled_at:
        return Response({'message': 'This order was cancelled.'}, status=status.HTTP_400_BAD_REQUEST)

    # The reference MUST be the one we issued for this order — prevents replaying a
    # successful reference from a different (cheaper or already-paid) order.
    if not order.payment_reference or not secrets.compare_digest(order.payment_reference, reference):
        return Response({'message': 'That payment reference does not match this order.'}, status=status.HTTP_400_BAD_REQUEST)

    if getattr(settings, 'PAYSTACK_SECRET_KEY', ''):
        ok, code, msg = _paystack_verify(reference, order)
        if not ok:
            return Response({'message': msg}, status=code)
    elif _paystack_mock_allowed():
        logger.warning("PAYSTACK_SECRET_KEY not configured; skipping live verification (dev mode).")
    else:
        return Response({'message': 'Payments are not configured yet. Please contact support.'}, status=status.HTTP_503_SERVICE_UNAVAILABLE)

    order = _mark_order_paid(order, user.email, reference)
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([])
@permission_classes([AllowAny])
def paystack_webhook_view(request):
    """
    Paystack server-to-server webhook. Handles the case where a student closes the
    browser mid-payment (common with MoMo approvals). Authenticity is proven by the
    HMAC-SHA512 signature of the raw body using our secret key.
    """
    secret_key = getattr(settings, 'PAYSTACK_SECRET_KEY', '')
    signature = request.headers.get('X-Paystack-Signature', '')
    if not secret_key or not signature:
        return Response({'ok': False}, status=status.HTTP_400_BAD_REQUEST)
    expected = hmac.new(secret_key.encode('utf-8'), request.body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, signature):
        logger.warning("Rejected Paystack webhook with invalid signature.")
        return Response({'ok': False}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return Response({'ok': False}, status=status.HTTP_400_BAD_REQUEST)

    if payload.get('event') == 'charge.success':
        reference = str((payload.get('data') or {}).get('reference') or '')
        order = Order.objects.filter(payment_reference=reference).first() if reference else None
        if order and not order.cancelled_at and order.payment_status not in ['paid', 'released']:
            # Re-verify with Paystack rather than trusting the payload amount blindly
            ok, _, _ = _paystack_verify(reference, order)
            if ok:
                _mark_order_paid(order, 'paystack_webhook', reference)
    # Always 200 so Paystack stops retrying once the signature is valid
    return Response({'ok': True})


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def payouts_ledger_view(request):
    """
    Calculates escrow earnings ledger for a chef:
    held vs released totals. Menu price goes to chef; 5% fee belongs to STEW.
    """
    user = request.user
    vendor = Vendor.objects.filter(user=user).first()
    if not vendor and not is_platform_admin(user):
        return Response({'held': 0, 'released': 0, 'heldCount': 0, 'releasedCount': 0, 'collected': 0, 'fees': 0})

    orders_query = Order.objects.filter(cancelled_at__isnull=True)
    if not is_platform_admin(user):
        orders_query = orders_query.filter(vendor=vendor)

    paid_qs = orders_query.filter(payment_status__in=['paid', 'released'])
    held_agg = paid_qs.filter(payment_status='paid').exclude(settlement_status='released').aggregate(
        held_sum=Sum('subtotal'), held_count=Count('id')
    )
    released_agg = paid_qs.filter(settlement_status='released').aggregate(
        released_sum=Sum('subtotal'), released_count=Count('id')
    )
    fees_agg = paid_qs.aggregate(fees_sum=Sum('fee'), total_collected=Sum('total'))

    return Response({
        'held': round(float(held_agg['held_sum'] or 0), 2),
        'released': round(float(released_agg['released_sum'] or 0), 2),
        'heldCount': held_agg['held_count'] or 0,
        'releasedCount': released_agg['released_count'] or 0,
        'collected': round(float(fees_agg['total_collected'] or 0), 2),
        'fees': round(float(fees_agg['fees_sum'] or 0), 2),
        'note': "STEW holds each payment until the student confirms collection, then releases it to you. You keep the full menu price; the 5% fee is added to the student's total."
    })


# ============================================================================
# MEETUP & HANDOVER ESCROW CONFIRMATION
# ============================================================================

def _release_escrow(order, collected_via: str, actor_email: str) -> None:
    """Marks an order as collected and releases its escrow payment to the vendor.

    Called by both student-confirmation and handoff-code paths. Idempotent if
    ``order.collected_at`` is already set (callers check before calling).
    """
    now = dj_timezone.now()
    now_ms = int(now.timestamp() * 1000)
    prep_at = order.prep_at or {}
    prep_at['collected'] = now_ms
    with transaction.atomic():
        order.collected_at = now
        order.collected_via = collected_via
        order.prep_stage = 'collected'
        order.prep_at = prep_at
        order.settlement_status = 'released'
        order.settlement_released_at = now
        order.settlement_net = order.subtotal
        order.payment_status = 'released'
        order.save(update_fields=[
            'collected_at', 'collected_via', 'prep_stage', 'prep_at',
            'settlement_status', 'settlement_released_at', 'settlement_net',
            'payment_status',
        ])
        audit_action = 'collection_confirmed' if collected_via == 'student_confirmed' else 'handoff_code_verified'
        record_audit(actor_email, audit_action, 'order', order.id, {'collectedVia': collected_via})


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def propose_meetup_view(request, pk):
    """Proposes a safe meeting spot for order collection."""
    if not check_rate_limit(f"meetup_{request.user.id}", limit=20, window_seconds=60):
        return Response({'message': 'Too many meetup requests. Please wait a moment.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_participant(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    terminal = _terminal_order_response(order)
    if terminal:
        return terminal

    place = escape(str(request.data.get('place', '')).strip()[:200])
    if len(place) < 3:
        return Response({'message': 'Please provide a valid meeting point.'}, status=status.HTTP_400_BAD_REQUEST)
    note = escape(str(request.data.get('note', '')).strip()[:300])
    # Determine proposedBy from actual user identity — never trust client input for role
    _user = request.user
    proposed_by = 'vendor' if _is_order_vendor(_user, order) else 'student'

    order.meetup = {
        'place': place,
        'note': note,
        'proposedBy': proposed_by,
        'proposedAt': int(dj_timezone.now().timestamp() * 1000),
        'confirmedBy': [proposed_by],
        'agreed': False
    }
    order.save(update_fields=['meetup'])
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def confirm_meetup_view(request, pk):
    """Confirms the proposed meeting point."""
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_participant(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    terminal = _terminal_order_response(order)
    if terminal:
        return terminal

    if not order.meetup or not order.meetup.get('place'):
        return Response({'message': 'Nobody has proposed a meeting point yet'}, status=status.HTTP_400_BAD_REQUEST)

    who = 'vendor' if _is_order_vendor(request.user, order) else 'student'
    confirmed_by = list(set((order.meetup.get('confirmedBy') or []) + [who]))
    agreed = 'student' in confirmed_by and 'vendor' in confirmed_by

    order.meetup['confirmedBy'] = confirmed_by
    order.meetup['agreed'] = agreed
    order.meetup['agreedAt'] = int(dj_timezone.now().timestamp() * 1000) if agreed else None
    order.save(update_fields=['meetup'])
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def decline_meetup_view(request, pk):
    """Declines current meeting spot so another can be chosen."""
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_participant(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    terminal = _terminal_order_response(order)
    if terminal:
        return terminal

    order.meetup = None
    order.save(update_fields=['meetup'])
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def send_order_message_view(request, pk):
    """Sends a sanitized message between student and chef."""
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_participant(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    terminal = _terminal_order_response(order)
    if terminal:
        return terminal
    if not check_rate_limit(f"order_msg_{request.user.id}", limit=30, window_seconds=60):
        return Response({'message': 'Too many messages sent. Please slow down.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

    text = escape(str(request.data.get('text', '')).strip()[:500])
    # Determine sender role from actual authenticated identity — never trust client input
    _sender = request.user
    from_role = 'vendor' if _is_order_vendor(_sender, order) else 'student'
    if not text:
        return Response({'message': 'Type a message first'}, status=status.HTTP_400_BAD_REQUEST)

    messages = list(order.messages or [])
    if len(messages) >= 100:
        return Response({'message': 'Message limit reached for this order.'}, status=status.HTTP_400_BAD_REQUEST)
    messages.append({
        'from': from_role,
        'text': text,
        'at': int(dj_timezone.now().timestamp() * 1000)
    })
    order.messages = messages
    order.save(update_fields=['messages'])
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def set_prep_stage_view(request, pk):
    """Chef updates preparation stage for batch cooking."""
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_vendor_or_admin(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    blocked = _inactive_vendor_response(request.user, order.vendor)
    if blocked:
        return blocked
    terminal = _terminal_order_response(order)
    if terminal:
        return terminal
    if order.payment_status not in ('paid', 'released'):
        return Response(
            {'message': 'Cannot advance preparation for an unpaid or refunded order.'},
            status=status.HTTP_400_BAD_REQUEST,
        )

    stage = request.data.get('stage')
    # Never allow 'collected' via set_prep_stage — collection requires student confirmation or handover code
    valid_stages = ['accepted', 'shopping', 'cooking', 'packing', 'ready']
    if stage not in valid_stages:
        return Response({'message': 'Invalid preparation stage'}, status=status.HTTP_400_BAD_REQUEST)

    prep_at = order.prep_at or {}
    now_ms = int(dj_timezone.now().timestamp() * 1000)
    prep_at[stage] = now_ms

    order.prep_stage = stage
    order.prep_at = prep_at
    order.save(update_fields=['prep_stage', 'prep_at'])
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def mark_collected_view(request, pk):
    """
    Student confirms collection of the food.
    This triggers release of escrow payment to the chef.
    Only the customer who placed the order may confirm collection.
    """
    _collector = request.user
    with transaction.atomic():
        try:
            order = Order.objects.select_for_update().select_related('vendor', 'customer').get(id=pk)
        except Order.DoesNotExist:
            return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        # IDOR protection: only the order's customer (or admin) may confirm collection
        if order.customer != _collector and order.email != _collector.email and not is_platform_admin(_collector):
            return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)

        if order.cancelled_at:
            return Response({'message': 'This order was cancelled'}, status=status.HTTP_400_BAD_REQUEST)
        if order.payment_status not in ['paid', 'released']:
            return Response({'message': 'This order was never paid for'}, status=status.HTTP_400_BAD_REQUEST)

        if order.collected_at:
            return Response(OrderSerializer(order, context={'request': request}).data)

        _release_escrow(order, 'student_confirmed', _collector.email)
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def complete_by_code_view(request, pk):
    """
    Chef verifies student's 6-digit handover code at collection.
    Constant-time comparison ensures no timing-attack leakage.
    Releases escrow funds.
    """
    with transaction.atomic():
        try:
            order = Order.objects.select_for_update().select_related('vendor').get(id=pk)
        except Order.DoesNotExist:
            return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        if not _is_order_vendor_or_admin(request.user, order):
            return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
        blocked = _inactive_vendor_response(request.user, order.vendor)
        if blocked:
            return blocked

        if order.cancelled_at:
            return Response({'message': 'This order was cancelled'}, status=status.HTTP_400_BAD_REQUEST)

        if order.payment_status not in ['paid', 'released']:
            return Response({'message': 'This order was never paid for'}, status=status.HTTP_400_BAD_REQUEST)

        if not check_rate_limit(f"handoff_try_{order.id}", limit=5, window_seconds=600):
            return Response({'message': 'Too many failed handover code attempts. Please wait 10 minutes.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)

        code = str(request.data.get('code', '')).strip()
        if not code or not order.handoff_code or not secrets.compare_digest(code, str(order.handoff_code).strip()):
            return Response({'message': 'That code does not match this order'}, status=status.HTTP_400_BAD_REQUEST)

        if order.collected_at:
            return Response(OrderSerializer(order, context={'request': request}).data)

        _release_escrow(order, 'handoff_code', request.user.email)
    return Response(OrderSerializer(order, context={'request': request}).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def collection_nudge_view(request, pk):
    """Chef nudges student to confirm collection."""
    try:
        order = Order.objects.get(id=pk)
    except Order.DoesNotExist:
        return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

    if not _is_order_vendor_or_admin(request.user, order):
        return Response({'message': 'Permission denied.'}, status=status.HTTP_403_FORBIDDEN)
    blocked = _inactive_vendor_response(request.user, order.vendor)
    if blocked:
        return blocked

    order.collection_nudged_at = dj_timezone.now()
    order.save(update_fields=['collection_nudged_at'])
    return Response(OrderSerializer(order, context={'request': request}).data)


# ============================================================================
# REVIEWS & MODERATION
# ============================================================================

def _recompute_vendor_rating(vendor):
    """Recalculates vendor rating and review count from all non-hidden customer reviews."""
    if not vendor:
        return
    agg = Review.objects.filter(vendor=vendor).exclude(moderation_status='hidden').aggregate(
        avg=Avg('rating'), count=Count('id')
    )
    count = agg['count'] or 0
    if count > 0:
        vendor.rating = round(agg['avg'], 1)
        vendor.reviews = count
    else:
        vendor.rating = 0.0
        vendor.reviews = 0
    vendor.save(update_fields=['rating', 'reviews'])


@api_view(['GET'])
@permission_classes([AllowAny])
def vendor_reviews_view(request, vendorId):
    """Lists moderated reviews for a vendor."""
    wants_hidden = request.query_params.get('includeHidden') == 'true'
    allow_hidden = False
    if wants_hidden:
        try:
            auth_res = JWTAuthentication().authenticate(request)
            if auth_res and is_platform_admin(auth_res[0]):
                allow_hidden = True
        except Exception:
            allow_hidden = False
    qs = Review.objects.filter(vendor__id=vendorId)
    if not allow_hidden:
        qs = qs.exclude(moderation_status='hidden')
    qs = _bound_queryset(request, qs)
    return Response(ReviewSerializer(qs, many=True).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def create_review_view(request):
    """Customer submits a review for a completed order."""
    if not check_rate_limit(f"review_{request.user.id}", limit=10, window_seconds=60):
        return Response({'message': 'Too many review submissions. Please wait a moment.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    order_id = request.data.get('orderId')
    _reviewer = request.user
    try:
        rating = int(request.data.get('rating', 5))
    except (TypeError, ValueError):
        return Response({'errors': {'rating': 'Rating must be 1 to 5 stars.'}}, status=status.HTTP_400_BAD_REQUEST)
    rating = max(1, min(5, rating))
    raw_tags = request.data.get('tags', [])
    tags = [escape(str(t).strip())[:40] for t in raw_tags[:8] if str(t).strip()] if isinstance(raw_tags, list) else []
    text = escape(str(request.data.get('text', '') or '').strip())[:1000]

    with transaction.atomic():
        try:
            order = Order.objects.select_for_update().select_related('vendor', 'customer').get(id=order_id)
        except Order.DoesNotExist:
            return Response({'message': 'Order not found'}, status=status.HTTP_404_NOT_FOUND)

        # Only the customer who placed this order may review it
        if order.customer != _reviewer and order.email != _reviewer.email:
            return Response({'message': 'You can only review your own orders.'}, status=status.HTTP_403_FORBIDDEN)

        # Order must be collected to review
        if not order.collected_at and order.prep_stage != 'collected':
            return Response({'message': 'You can only review an order you have collected'}, status=status.HTTP_400_BAD_REQUEST)

        if Review.objects.filter(order_id=order_id).exists():
            return Response({'message': 'You have already reviewed this order'}, status=status.HTTP_400_BAD_REQUEST)

        if not order.vendor:
            return Response({'message': 'This kitchen is no longer on STEW, so it cannot be reviewed.'}, status=status.HTTP_400_BAD_REQUEST)

        review = Review.objects.create(
            order_id=order_id,
            vendor=order.vendor,
            vendor_name=order.vendor_name,
            customer=_reviewer,
            rating=rating,
            tags=tags,
            text=text,
            moderation_status='pending'
        )
        _recompute_vendor_rating(order.vendor)
        record_audit(_reviewer.email, 'review_submitted', 'review', order_id, {'rating': rating})
    return Response(ReviewSerializer(review).data, status=status.HTTP_201_CREATED)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def moderation_queue_view(request):
    """Admin endpoint for pending reviews."""
    qs = _bound_queryset(request, Review.objects.filter(moderation_status='pending'))
    return Response(ReviewSerializer(qs, many=True).data)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def moderate_review_view(request, orderId):
    """Admin approves or hides a review."""
    try:
        review = Review.objects.get(order_id=orderId)
    except Review.DoesNotExist:
        return Response({'message': 'Review not found'}, status=status.HTTP_404_NOT_FOUND)

    VALID_DECISIONS = {'visible', 'hidden', 'pending'}
    decision = request.data.get('decision', 'visible')
    if decision not in VALID_DECISIONS:
        return Response(
            {'message': f'Invalid decision. Must be one of: {", ".join(sorted(VALID_DECISIONS))}.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    reason = escape(str(request.data.get('reason', '')).strip()[:500])

    review.moderation_status = decision
    review.moderation_reason = reason
    review.moderated_at = dj_timezone.now()
    review.save()

    _recompute_vendor_rating(review.vendor)

    record_audit(request.user.email, f"review_{decision}", 'review', orderId)
    return Response(ReviewSerializer(review).data)


# ============================================================================
# COMPLIANCE (FDA PERMIT)
# ============================================================================

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsVendorUser])
def vendor_compliance_view(request):
    """Retrieves or uploads vendor food safety compliance permit."""
    user = request.user
    if request.method == 'GET':
        comp = Compliance.objects.filter(vendor_id=user.email).first()
        return Response(ComplianceSerializer(comp).data if comp else None)

    data = request.data
    number = escape(str(data.get('number', '')).strip())
    perm_type = escape(str(data.get('type', 'FDA food hygiene permit')))
    issued_at = escape(str(data.get('issuedAt', '')))
    expires_at = escape(str(data.get('expiresAt', '')))

    comp, _ = Compliance.objects.update_or_create(
        vendor_id=user.email,
        defaults={
            'vendor_name': user.kitchen_name or user.full_name,
            'type': perm_type,
            'number': number,
            'issued_at': issued_at,
            'expires_at': expires_at,
        }
    )
    record_audit(user.email, 'compliance_submitted', 'compliance', comp.vendor_id)
    return Response(ComplianceSerializer(comp).data)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_compliance_view(request):
    """Admin inspects all vendor food hygiene permits."""
    qs = _bound_queryset(request, Compliance.objects.all())
    return Response(ComplianceSerializer(qs, many=True).data)


# ============================================================================
# PAYOUT BATCHES
# ============================================================================

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def payout_batches_view(request):
    """Admin view for aggregate vendor payout batches."""
    if request.method == 'GET':
        batches = _bound_queryset(request, PayoutBatch.objects.all().order_by('-created_at'))
        return Response(PayoutBatchSerializer(batches, many=True).data)

    # POST: Create a new payout batch under row lock so concurrent calls cannot double-settle
    batch_id = _unique_id(PayoutBatch, 'PAY')
    now = dj_timezone.now()

    with transaction.atomic():
        locked_ids = list(
            Order.objects.select_for_update()
            .filter(
                settlement_status='released',
                payout_batch_id__isnull=True,
                cancelled_at__isnull=True,
                vendor__active=True,
            )
            .values_list('id', flat=True)
        )
        if not locked_ids:
            return Response({'message': 'Nothing to settle yet — no released orders waiting.'}, status=status.HTTP_400_BAD_REQUEST)

        released_orders = Order.objects.filter(id__in=locked_ids)
        agg = released_orders.aggregate(
            total_amount=Sum('subtotal'),
            period_start=Min('collected_at'),
            period_end=Max('collected_at'),
            order_count=Count('id'),
        )
        batch_amount = Decimal(str(agg['total_amount'] or '0.00')).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
        batch = PayoutBatch.objects.create(
            id=batch_id,
            amount=batch_amount,
            currency='GHS',
            status='paid',
            order_count=agg['order_count'] or 0,
            period_start=agg['period_start'] or now,
            period_end=agg['period_end'] or now,
            provider='paystack',
            provider_reference=f"TRF-{secrets.token_hex(4).upper()}",
            paid_at=now
        )
        released_orders.update(payout_batch_id=batch.id)
        record_audit(request.user.email, 'payout_batch_created', 'payout_batch', batch.id, {'amount': float(batch.amount)})

    return Response(PayoutBatchSerializer(batch).data, status=status.HTTP_201_CREATED)


# ============================================================================
# SUPPORT CASES
# ============================================================================

@api_view(['GET', 'POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def support_cases_view(request):
    """Customer or Admin support tickets."""
    user = request.user
    if request.method == 'GET':
        if is_platform_admin(user):
            cases = SupportCase.objects.all().order_by('-created_at')
        else:
            cases = SupportCase.objects.filter(user=user).order_by('-created_at')
        cases = _bound_queryset(request, cases)
        return Response(SupportCaseSerializer(cases, many=True).data)

    data = request.data
    if not check_rate_limit(f"support_{user.id}", limit=10, window_seconds=3600):
        return Response({'message': 'You have opened several cases recently. Please wait before opening another.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    case_code = _unique_id(SupportCase, 'CASE')
    case_type = escape(str(data.get('type', 'missing')))[:32]
    priority = 'high' if case_type == 'safety' else 'normal'
    raw_order_id = str(data.get('order') or data.get('orderId') or '').strip()[:64]
    raw_vendor = str(data.get('vendor') or '').strip()
    if raw_order_id:
        order_obj = Order.objects.filter(id=raw_order_id).first()
        if not order_obj:
            return Response({'message': 'Order not found.'}, status=status.HTTP_404_NOT_FOUND)
        # A student may only attach orders they are part of — no probing other orders
        if not _is_order_participant(user, order_obj):
            return Response({'message': 'You can only report your own orders.'}, status=status.HTTP_403_FORBIDDEN)
        if order_obj.payment_status in ('refunded', 'refund_pending', 'cancelled'):
            return Response({'message': 'This order has already been refunded or cancelled.'}, status=status.HTTP_400_BAD_REQUEST)
        if SupportCase.objects.filter(user=user, order=escape(raw_order_id)).exists():
            return Response({'message': 'An open support case already exists for this order.'}, status=status.HTTP_400_BAD_REQUEST)
        if not raw_vendor:
            raw_vendor = order_obj.vendor_name
    raw_note = str(data.get('note') or data.get('description') or '').strip()[:1000]

    case = SupportCase.objects.create(
        code=case_code,
        user=user,
        type=case_type,
        order=escape(raw_order_id),
        vendor=escape(raw_vendor[:150]),
        priority=priority,
        note=escape(raw_note)
    )
    return Response(SupportCaseSerializer(case).data, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def support_case_resolve_view(request, code):
    """Admin endpoint to resolve/close a support case (refund or dismiss)."""
    try:
        case = SupportCase.objects.get(code=code)
    except SupportCase.DoesNotExist:
        return Response({'message': 'Support case not found.'}, status=status.HTTP_404_NOT_FOUND)

    action = str(request.data.get('action') or 'dismiss').lower()
    if action not in ('refund', 'dismiss'):
        return Response({'message': 'Invalid resolution action.'}, status=status.HTTP_400_BAD_REQUEST)

    if action == 'refund' and case.order:
        with transaction.atomic():
            order = Order.objects.select_for_update().filter(id=case.order).first()
            if order and not order.cancelled_at:
                was_uncollected = not order.collected_at and order.prep_stage != 'collected'
                now = dj_timezone.now()
                order.cancelled_at = now
                was_paid = order.payment_status in ('paid', 'released')
                if was_paid and order.settlement_status == 'released':
                    order.payment_status = 'refund_pending'
                elif was_paid:
                    order.payment_status = 'refunded'
                else:
                    order.payment_status = 'cancelled'
                order.save(update_fields=['cancelled_at', 'payment_status'])
                if was_uncollected:
                    _restore_order_stock(order)
                record_audit(request.user.email, f'case_refund_order_cancelled', 'order', order.id, {'case': case.code})

    record_audit(request.user.email, f'case_{action}', 'support_case', case.code, {'order': case.order, 'vendor': case.vendor})
    case.delete()
    return Response({'ok': True, 'code': code, 'action': action})


# ============================================================================
# ADMIN MANAGEMENT ENDPOINTS
# ============================================================================

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_vendors_view(request):
    """Admin list of all kitchens (both active and inactive)."""
    vendors = _bound_queryset(request, Vendor.objects.all().order_by('-created_at'))
    return Response(VendorSerializer(vendors, many=True).data)


@api_view(['PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_vendor_detail_view(request, pk):
    """Admin toggle of a vendor's active or open status."""
    try:
        vendor = Vendor.objects.get(pk=pk)
    except Vendor.DoesNotExist:
        return Response({'message': 'Vendor not found.'}, status=status.HTTP_404_NOT_FOUND)

    data = request.data
    if 'active' in data:
        vendor.active = bool(data['active'])
    if 'open' in data:
        vendor.open = bool(data['open'])
    vendor.save()
    record_audit(request.user.email, 'admin_vendor_updated', 'vendor', vendor.id, {'active': vendor.active, 'open': vendor.open})
    return Response(VendorSerializer(vendor).data)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_users_view(request):
    """Admin list of all student accounts."""
    users = _bound_queryset(request, User.objects.all().order_by('-created_at'))
    return Response(AdminUserSerializer(users, many=True).data)


@api_view(['PATCH'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_user_detail_view(request, pk):
    """Admin toggle of a user's active status."""
    try:
        target = User.objects.get(pk=pk)
    except User.DoesNotExist:
        return Response({'message': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    if is_platform_admin(target):
        return Response({'message': 'Admin accounts cannot be suspended from the dashboard.'}, status=status.HTTP_400_BAD_REQUEST)

    if 'active' in request.data:
        target.is_active = bool(request.data['active'])
        target.save(update_fields=['is_active'])
        record_audit(request.user.email, 'admin_user_status', 'user', target.id, {'active': target.is_active})

    return Response(AdminUserSerializer(target).data)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAdminUser])
def admin_audit_view(request):
    """Admin read-only audit log feed."""
    entries = AuditEntry.objects.all().order_by('-at')[:200]
    return Response(AuditEntrySerializer(entries, many=True).data)


# ============================================================================
# PUSH NOTIFICATIONS & ANALYTICS
# ============================================================================

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def subscribe_push_view(request):
    """Subscribes student device to push notifications."""
    if not check_rate_limit(f"push_sub_{request.user.id}", limit=15, window_seconds=60):
        return Response({'message': 'Too many subscription requests. Please wait.'}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    endpoint = str(request.data.get('endpoint') or '').strip()[:500]
    if not endpoint or not endpoint.startswith('https://'):
        return Response({'message': 'Push subscription endpoint must use https://'}, status=status.HTTP_400_BAD_REQUEST)
    PushSubscription.objects.update_or_create(
        endpoint=endpoint,
        defaults={'user': request.user, 'keys': request.data.get('keys', {})}
    )
    return Response({'ok': True}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsStudentUser])
def unsubscribe_push_view(request):
    """Unsubscribes student device from push notifications."""
    endpoint = str(request.data.get('endpoint') or '').strip()[:500]
    if endpoint:
        PushSubscription.objects.filter(endpoint=endpoint, user=request.user).delete()
    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([AllowAny])
def analytics_event_view(request):
    """Anonymous event tracking endpoint."""
    # Rate-limit by IP to prevent DB flooding from this unauthenticated endpoint
    _ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    if not check_rate_limit(f"analytics_{_ip}", limit=30, window_seconds=60):
        return Response({'ok': True})  # Silent drop — don't reveal rate-limit to callers
    event = escape(str(request.data.get('event', 'unknown'))[:100])
    # Store a sanitized subset of the payload — never store raw arbitrary JSON
    safe_payload = {
        'event': event,
        'page': escape(str(request.data.get('page', ''))[:200]),
    }
    AnalyticsEvent.objects.create(event=event, payload=safe_payload)
    return Response({'ok': True})
