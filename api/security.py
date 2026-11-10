import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
import jwt

# In-memory rate limiting cache for sensitive endpoints (IP / identifier based).
# PRODUCTION NOTE: Replace _RATE_LIMIT_CACHE with a Redis-backed Django cache for
# multi-worker deployments — this in-memory dict resets on every Gunicorn worker restart.
_RATE_LIMIT_CACHE = {}


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
# Default: 24 hours. For production, consider 1 hour + refresh token flow.
_JWT_LIFETIME_HOURS = int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME_HOURS', 24))


def password_fingerprint(user) -> str:
    """Short fingerprint of the stored password hash. Changes whenever the password changes,
    so every token issued before a password reset stops working immediately."""
    return hashlib.sha256(f"{user.password}|{settings.SECRET_KEY}".encode('utf-8')).hexdigest()[:16]


def generate_jwt_token(user) -> str:
    """Generates a signed JWT access token. Lifetime controlled by JWT_ACCESS_TOKEN_LIFETIME_HOURS."""
    now = datetime.now(timezone.utc)
    lifetime = int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME_HOURS', 24))
    payload = {
        'sub': str(user.id),
        'role': user.role,
        'pv': password_fingerprint(user),
        'iat': int(now.timestamp()),
        'exp': int((now + timedelta(hours=lifetime)).timestamp()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')


def decode_jwt_token(token: str) -> dict:
    """Decodes and validates a JWT access token."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Token has expired. Please log in again.')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid authorization token.')


def check_rate_limit(key: str, limit: int = 5, window_seconds: int = 60) -> bool:
    """
    Simple in-memory sliding-window rate limiter.
    Returns True if allowed, False if exceeded.
    PRODUCTION: Replace with Redis-backed cache for multi-worker safety.
    """
    now = time.time()
    attempts = _RATE_LIMIT_CACHE.get(key, [])
    # Filter attempts within the sliding window
    attempts = [t for t in attempts if now - t < window_seconds]
    if len(attempts) >= limit:
        _RATE_LIMIT_CACHE[key] = attempts
        return False
    attempts.append(now)
    _RATE_LIMIT_CACHE[key] = attempts
    return True
