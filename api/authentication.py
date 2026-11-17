import hmac
from rest_framework import authentication, permissions
from rest_framework.exceptions import AuthenticationFailed
from api.models import User
from api.security import decode_jwt_token, password_fingerprint
from api.validators import KNUST_STUDENT_EMAIL_REGEX


class JWTAuthentication(authentication.BaseAuthentication):
    """
    Custom JWT Authentication for STEW API.
    Extracts Bearer token from the Authorization header and verifies the user.
    """
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return None

        parts = auth_header.strip().split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return None

        token = parts[1]
        payload = decode_jwt_token(token)

        user_id = payload.get('sub')
        if not user_id:
            raise AuthenticationFailed('Invalid token payload.')

        try:
            user = User.objects.get(id=user_id, is_active=True, verified=True)
        except User.DoesNotExist:
            raise AuthenticationFailed('User account is not verified or has been disabled.')

        # Tokens issued before the latest password change/reset are revoked
        if not hmac.compare_digest(str(payload.get('pv', '')), password_fingerprint(user)):
            raise AuthenticationFailed('Your session has expired. Please log in again.')

        # Defensive check: ensure email is strictly a KNUST student email
        if not KNUST_STUDENT_EMAIL_REGEX.match(user.email):
            raise AuthenticationFailed('Access restricted: Only KNUST students with @st.knust.edu.gh emails are authorized.')

        return (user, token)

    def authenticate_header(self, request):
        return 'Bearer realm="api"'


def is_platform_admin(user) -> bool:
    """Single canonical check for STEW platform administrators."""
    return bool(user and user.is_authenticated and user.is_admin)


class IsStudentUser(permissions.BasePermission):
    """Allows access only to authenticated, verified KNUST student users."""
    def has_permission(self, request, view):
        return bool(
            request.user
            and request.user.is_authenticated
            and request.user.is_active
            and request.user.verified
        )


class IsVendorUser(permissions.BasePermission):
    """Allows access to verified users who are vendors, both, or administrators."""
    def has_permission(self, request, view):
        if not (
            request.user
            and request.user.is_authenticated
            and request.user.is_active
            and request.user.verified
        ):
            return False
        return bool(
            request.user.is_vendor
            or request.user.role == 'vendor'
            or request.user.account_type in ['vendor', 'both']
            or is_platform_admin(request.user)
        )


class IsAdminUser(permissions.BasePermission):
    """Allows access only to administrator users."""
    def has_permission(self, request, view):
        return is_platform_admin(request.user)
