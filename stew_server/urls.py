from django.contrib import admin
from django.urls import path, include
from api.authentication import is_platform_admin


def _admin_has_permission(request):
    user = getattr(request, 'user', None)
    return bool(
        user
        and user.is_authenticated
        and user.is_active
        and getattr(user, 'verified', False)
        and is_platform_admin(user)
    )


admin.site.has_permission = _admin_has_permission

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('api.urls')),
]
