import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')

# ---------------------------------------------------------------------------
# SECURITY — never set a production SECRET_KEY here; use the .env file.
# ---------------------------------------------------------------------------
_raw_key = os.getenv('SECRET_KEY', '')
_key_lower = _raw_key.lower()
# Default to False — production must explicitly set DEBUG=True in .env to enable debug mode.
DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 'yes')

_is_weak_key = (
    len(_raw_key) < 32
    or any(w in _key_lower for w in ('django-insecure', 'replace_me', 'placeholder', 'dev-only', 'change-me'))
)
if _is_weak_key:
    if not DEBUG:
        raise RuntimeError(
            "Refusing to start STEW in production (DEBUG=False) with a missing or placeholder SECRET_KEY. "
            "Generate a strong key with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )
    import warnings
    warnings.warn(
        "⚠  STEW WARNING: SECRET_KEY is missing or still set to the insecure "
        "development placeholder. Generate a proper key with: "
        "python -c \"import secrets; print(secrets.token_urlsafe(64))\" "
        "and place it in your .env file before deploying.",
        stacklevel=2,
    )
SECRET_KEY = _raw_key or 'django-insecure-stew-secret-key-knust-campus-2026-dev-only'

_allowed = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1')
ALLOWED_HOSTS = [h.strip() for h in _allowed.split(',') if h.strip()]

# Reject wildcard ALLOWED_HOSTS in production
if not DEBUG and '*' in ALLOWED_HOSTS:
    raise RuntimeError(
        "ALLOWED_HOSTS='*' is not permitted in production (DEBUG=False). "
        "Set ALLOWED_HOSTS to your actual domain names."
    )

# Custom Student User Model
AUTH_USER_MODEL = 'api.User'

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third-party apps
    'corsheaders',
    'rest_framework',
    # STEW backend app
    'api',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'api.security.SecurityHeadersMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'stew_server.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'stew_server.wsgi.application'

# ---------------------------------------------------------------------------
# DATABASE
# Development: SQLite (zero-config).
# Production: set DB_ENGINE=postgresql plus DB_NAME, DB_USER, DB_PASSWORD, etc.
# ---------------------------------------------------------------------------
_db_engine = os.getenv('DB_ENGINE', 'sqlite3')
if _db_engine == 'postgresql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'stew'),
            'USER': os.getenv('DB_USER', 'stew_user'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': 60,
            'OPTIONS': {
                'sslmode': os.getenv('DB_SSLMODE', 'require'),
            },
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

REDIS_URL = os.getenv('REDIS_URL', '').strip()
if REDIS_URL:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': REDIS_URL,
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
            'LOCATION': 'stew-default-cache',
        }
    }
RATE_LIMIT_BACKEND = 'db'

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Africa/Accra'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ---------------------------------------------------------------------------
# Proxy / Rate Limiting Trust Boundary
# 0 (default): ignore X-Forwarded-For and use REMOTE_ADDR only.
# N > 0: take the Nth IP from the RIGHT of X-Forwarded-For (trusted proxies).
# ---------------------------------------------------------------------------
TRUSTED_PROXY_COUNT = max(0, int(os.getenv('TRUSTED_PROXY_COUNT', '0')))

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'api.authentication.JWTAuthentication',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
    ],
    'EXCEPTION_HANDLER': 'api.exceptions.custom_exception_handler',
    # Global DRF throttling as a safety net; per-view rate limiting is in security.py
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '300/min',
        'user': '120/min',
    },
    'NUM_PROXIES': TRUSTED_PROXY_COUNT,
}

# ---------------------------------------------------------------------------
# CORS — restrict to allowed frontend origins.
# Dev default: localhost Vite dev server. Production: set CORS_ALLOWED_ORIGINS env var.
# ---------------------------------------------------------------------------
_cors_env = os.getenv('CORS_ALLOWED_ORIGINS', '')
if _cors_env:
    CORS_ALLOWED_ORIGINS = [o.strip() for o in _cors_env.split(',') if o.strip()]
else:
    CORS_ALLOWED_ORIGINS = [
        'http://localhost:5173',
        'http://127.0.0.1:5173',
        'http://localhost:3000',
    ]

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = [
    'accept',
    'accept-encoding',
    'authorization',
    'content-type',
    'dnt',
    'origin',
    'user-agent',
    'x-csrftoken',
    'x-requested-with',
]
CORS_EXPOSE_HEADERS = [
    'X-Total-Count',
    'X-Result-Limit',
    'X-Result-Offset',
    'X-Truncated',
]

# ---------------------------------------------------------------------------
# Security headers — always-on baseline; production adds HTTPS-specific headers
# ---------------------------------------------------------------------------
# Always enforce these regardless of DEBUG mode
DATA_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',')
    if origin.strip()
]

if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000        # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    # Trust the X-Forwarded-Proto header from reverse proxies (nginx, Caddy, etc.)
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'api': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.security': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# ---------------------------------------------------------------------------
# Email Configuration (OTP delivery)
# Defaults to console backend in DEBUG mode so verification codes appear in the terminal.
# ---------------------------------------------------------------------------
EMAIL_BACKEND = os.getenv(
    'EMAIL_BACKEND',
    'django.core.mail.backends.console.EmailBackend' if DEBUG else 'django.core.mail.backends.smtp.EmailBackend',
)
if not DEBUG and EMAIL_BACKEND == 'django.core.mail.backends.console.EmailBackend':
    raise RuntimeError(
        "EMAIL_BACKEND cannot be 'django.core.mail.backends.console.EmailBackend' in production (DEBUG=False). "
        "Configure an SMTP or transactional email backend so verification codes are never written to stdout."
    )
DEFAULT_FROM_EMAIL = os.getenv('DEFAULT_FROM_EMAIL', 'STEW KNUST <noreply@stew.knust.edu.gh>')
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', '587'))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() in ('true', '1', 'yes')

# ---------------------------------------------------------------------------
# Paystack API Keys (never commit real keys to version control)
# ---------------------------------------------------------------------------
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', '')
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
# Simulated payments (no Paystack call) are only ever allowed in DEBUG unless explicitly opted in.
# In production with no secret key, payment endpoints refuse with 503 instead of marking orders paid.
PAYSTACK_ALLOW_MOCK = os.getenv('PAYSTACK_ALLOW_MOCK', 'True' if DEBUG else 'False').lower() in ('true', '1', 'yes')
if not DEBUG and PAYSTACK_ALLOW_MOCK:
    raise RuntimeError("PAYSTACK_ALLOW_MOCK must not be enabled in production (DEBUG=False).")

# ---------------------------------------------------------------------------
# JWT token lifetime (hours). Override with JWT_ACCESS_TOKEN_LIFETIME_HOURS env var.
# Default: 24 hours. Use a shorter value (e.g. 1) + refresh tokens in production.
# ---------------------------------------------------------------------------
JWT_ACCESS_TOKEN_LIFETIME_HOURS = int(os.getenv('JWT_ACCESS_TOKEN_LIFETIME_HOURS', '24'))

# ---------------------------------------------------------------------------
# PRODUCTION NOTES:
# - In-memory rate limiting (security.py _RATE_LIMIT_CACHE) resets on every
#   worker restart. For multi-worker/multi-server deployments, replace with
#   a Redis-backed cache. Set CACHES to use django-redis and update
#   check_rate_limit() to use Django's cache framework.
# - Set SESSION_ENGINE to use database or cache sessions in production.
# - Rotate SECRET_KEY by generating: python -c "import secrets; print(secrets.token_urlsafe(64))"
# - Wire up email sending (EMAIL_HOST etc.) so OTP codes are actually delivered.
# ---------------------------------------------------------------------------
