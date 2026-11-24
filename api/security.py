import hashlib
import hmac
import ipaddress
import re
import secrets
from datetime import datetime, timedelta, timezone
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
import jwt


def get_client_ip(request) -> str:
    """
    Returns the client IP address for rate-limiting.
    When settings.TRUSTED_PROXY_COUNT <= 0 (default), uses REMOTE_ADDR only.
    When settings.TRUSTED_PROXY_COUNT == N > 0, takes the Nth IP from the RIGHT
    of X-Forwarded-For (appended by trusted proxies), never trusting left-most entries.
    """
    meta = getattr(request, 'META', None) or {}
    remote_addr = str(meta.get('REMOTE_ADDR') or '127.0.0.1').strip() or '127.0.0.1'
    try:
        trusted_count = int(getattr(settings, 'TRUSTED_PROXY_COUNT', 0) or 0)
    except (TypeError, ValueError):
        trusted_count = 0
    if trusted_count <= 0:
        return remote_addr

    xff = str(meta.get('HTTP_X_FORWARDED_FOR') or '').strip()
    if not xff:
        return remote_addr
    parts = [p.strip() for p in xff.split(',') if p.strip()]
    if len(parts) < trusted_count:
        return remote_addr
    candidate = parts[-trusted_count]
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return remote_addr


class _RateLimitCacheStore(dict):
    """Compatibility store so _RATE_LIMIT_CACHE.clear() resets DB buckets in tests."""

    def clear(self):
        super().clear()
        try:
            from django.core.cache import cache
            cache.clear()
        except Exception:
            pass
        try:
            from api.models import RateLimitBucket
            RateLimitBucket.objects.all().delete()
        except Exception:
            pass


_RATE_LIMIT_CACHE = _RateLimitCacheStore()


def hash_token(token: str) -> str:
    """Hashes a verification/reset/login code using SHA-256 with project salt."""
    salt = getattr(settings, 'SECRET_KEY', 'default-salt').encode('utf-8')
    return hashlib.sha256(salt + token.strip().encode('utf-8')).hexdigest()


def verify_hashed_token(token: str, expected_hash: str) -> bool:
    """Constant-time comparison between provided token and stored hash."""
    if not token or not expected_hash:
        return False
    computed = hash_token(token)
    return hmac.compare_digest(computed, expected_hash)


def generate_6digit_code() -> str:
    """Generates a cryptographically strong 6-digit numeric OTP code."""
    return f"{secrets.randbelow(900000) + 100000}"


# JWT access token lifetime. Configurable via settings.JWT_ACCESS_TOKEN_LIFETIME_HOURS.
# Default: 12 hours. For production with refresh tokens, consider 1 hour.
_JWT_LIFETIME_HOURS = int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME_HOURS', 12))


def password_fingerprint(user) -> str:
    """Short fingerprint of the stored password hash. Changes whenever the password changes,
    so every token issued before a password reset stops working immediately."""
    return hashlib.sha256(f"{user.password}|{settings.SECRET_KEY}".encode('utf-8')).hexdigest()[:16]


def generate_jwt_token(user) -> str:
    """Generates a signed JWT access token. Lifetime controlled by JWT_ACCESS_TOKEN_LIFETIME_HOURS."""
    now = datetime.now(timezone.utc)
    lifetime = int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME_HOURS', 12))
    payload = {
        'iss': 'stew',
        'sub': str(user.id),
        'jti': secrets.token_hex(16),
        'role': user.role,
        'pv': password_fingerprint(user),
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(hours=lifetime)).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def decode_jwt_token(token: str) -> dict:
    """Decodes and validates a JWT access token, requiring iss='stew'."""
    try:
        return jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=['HS256'],
            issuer='stew',
            options={'require': ['iss']},
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token has expired. Please log in again.')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid authorization token.')


def _revoked_jwt_key(token: str, payload: dict | None = None) -> str:
    jti = str((payload or {}).get('jti') or '').strip()
    if jti and len(f"jwt_revoked_{jti}") <= 255:
        return f"jwt_revoked_{jti}"
    digest = hashlib.sha256((jti or str(token)).encode('utf-8')).hexdigest()
    return f"jwt_revoked_{digest}"


def _normalize_rate_limit_key(key: str) -> str:
    raw = str(key or '')
    if 0 < len(raw) <= 200 and not raw.startswith('jwt_revoked_'):
        return raw
    return f"rl_sha256_{hashlib.sha256(raw.encode('utf-8')).hexdigest()}"


def revoke_jwt_token(token: str, payload: dict | None = None) -> None:
    """Records a JWT access token's jti (or hash fallback) in the persistent DB blocklist."""
    from django.utils import timezone as dj_timezone
    from api.models import RateLimitBucket

    if not token:
        return
    if payload is None:
        try:
            payload = decode_jwt_token(token)
        except AuthenticationFailed:
            payload = {}
    RateLimitBucket.objects.update_or_create(
        key=_revoked_jwt_key(token, payload),
        defaults={'count': 1, 'window_start': dj_timezone.now()},
    )


def is_jwt_revoked(token: str, payload: dict | None = None) -> bool:
    """Returns True if the JWT access token has been explicitly revoked."""
    from api.models import RateLimitBucket

    if not token and not payload:
        return False
    if payload is None and token:
        try:
            payload = decode_jwt_token(token)
        except AuthenticationFailed:
            payload = {}
    return RateLimitBucket.objects.filter(key=_revoked_jwt_key(token, payload)).exists()


class SecurityHeadersMiddleware:
    """Attaches Content-Security-Policy, Permissions-Policy, and no-store Cache-Control on sensitive API routes."""

    _SENSITIVE_API_PREFIXES = (
        '/api/auth/',
        '/api/orders/',
        '/api/payments/',
        '/api/payouts/',
        '/api/admin/',
        '/api/support/',
        '/api/notifications/',
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path.startswith('/admin/'):
            response.setdefault('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'self'")
        else:
            response.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        response.setdefault('Permissions-Policy', 'geolocation=(), camera=(), microphone=(), payment=()')
        if request.path.startswith('/api/') and (
            request.META.get('HTTP_AUTHORIZATION') or request.path.startswith(self._SENSITIVE_API_PREFIXES)
        ):
            response['Cache-Control'] = 'no-store, private'
            response['Pragma'] = 'no-cache'
        return response


def check_rate_limit(key: str, limit: int = 5, window_seconds: int = 60) -> bool:
    """
    Persistent atomic DB-backed sliding-window rate limiter.
    Survives process restarts and works across multiple worker processes.
    Returns True if allowed, False if exceeded.
    """
    from django.db import IntegrityError, transaction
    from django.utils import timezone as dj_timezone
    from api.models import RateLimitBucket

    bucket_key = _normalize_rate_limit_key(key)
    now = dj_timezone.now()
    window = timedelta(seconds=window_seconds)

    with transaction.atomic():
        bucket = RateLimitBucket.objects.select_for_update().filter(key=bucket_key).first()
        if bucket is None:
            try:
                with transaction.atomic():
                    RateLimitBucket.objects.create(key=bucket_key, count=1, window_start=now)
                    _RATE_LIMIT_CACHE[bucket_key] = [now.timestamp()]
                    return True
            except IntegrityError:
                bucket = RateLimitBucket.objects.select_for_update().get(key=bucket_key)

        if (now - bucket.window_start) >= window:
            bucket.count = 1
            bucket.window_start = now
            bucket.save(update_fields=['count', 'window_start', 'updated_at'])
            _RATE_LIMIT_CACHE[bucket_key] = [now.timestamp()]
            return True

        if bucket.count >= limit:
            return False

        bucket.count += 1
        bucket.save(update_fields=['count', 'updated_at'])
        _RATE_LIMIT_CACHE.setdefault(bucket_key, []).append(now.timestamp())
        return True


class ConfigurableAnonRateThrottle(AnonRateThrottle):
    """DRF AnonRateThrottle reading settings.THROTTLE_ANON_PER_MIN dynamically."""

    def get_rate(self):
        val = getattr(settings, 'THROTTLE_ANON_PER_MIN', None)
        if val is not None:
            return f"{max(1, int(val))}/min"
        return super().get_rate()


class ConfigurableUserRateThrottle(UserRateThrottle):
    """DRF UserRateThrottle reading settings.THROTTLE_USER_PER_MIN dynamically for authenticated users only."""

    def get_cache_key(self, request, view):
        if not (request.user and request.user.is_authenticated):
            return None
        return super().get_cache_key(request, view)

    def get_rate(self):
        val = getattr(settings, 'THROTTLE_USER_PER_MIN', None)
        if val is not None:
            return f"{max(1, int(val))}/min"
        return super().get_rate()


_PHONE_RE = re.compile(
    r'(?:\+?233[\s\-]*(?:\(0\)[\s\-]*)?|(?<!\d)0)\d(?:[\s\-]*\d){8}(?!\d)'
    r'|(?<!\d)\d(?:[\s\-]*\d){8,}(?!\d)'
)


def mask_phone_numbers(text: str) -> tuple[str, bool]:
    """Mask Ghana phone numbers and 9+ digit sequences to [phone hidden]."""
    if not text:
        return text or '', False
    masked, count = _PHONE_RE.subn('[phone hidden]', str(text))
    return masked, count > 0
