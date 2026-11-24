from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from api.models import FailedLoginEvent, RateLimitBucket

# Longest rate-limit window used across api/views.py (3600s for register/reset/support)
LONGEST_RATE_LIMIT_WINDOW_SECONDS = 3600
REVOKED_JWT_PREFIX = 'jwt_revoked_'


def _delete_in_batches(queryset, batch_size: int, model=RateLimitBucket, pk_field: str = 'key') -> int:
    """Deletes matching rows in bounded batches to avoid table-wide locks."""
    total_deleted = 0
    while True:
        batch_keys = list(queryset.order_by(pk_field).values_list(pk_field, flat=True)[:batch_size])
        if not batch_keys:
            break
        deleted, _ = model.objects.filter(**{f'{pk_field}__in': batch_keys}).delete()
        total_deleted += deleted
    return total_deleted


class Command(BaseCommand):
    help = 'Delete expired rate-limit buckets and expired JWT revocation rows in batches.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--batch-size',
            type=int,
            default=1000,
            help='Maximum number of rows deleted per SQL statement (default: 1000).',
        )
        parser.add_argument(
            '--margin-seconds',
            type=int,
            default=3600,
            help='Safety margin added beyond window/JWT lifetime before purging (default: 3600).',
        )

    def handle(self, *args, **options):
        batch_size = max(1, int(options['batch_size']))
        margin_seconds = max(0, int(options['margin_seconds']))
        jwt_hours = max(1, int(getattr(settings, 'JWT_ACCESS_TOKEN_LIFETIME_HOURS', 12)))

        now = timezone.now()
        rate_limit_cutoff = now - timedelta(seconds=LONGEST_RATE_LIMIT_WINDOW_SECONDS + margin_seconds)
        revocation_cutoff = now - timedelta(hours=jwt_hours, seconds=margin_seconds)

        rl_qs = RateLimitBucket.objects.filter(window_start__lt=rate_limit_cutoff).exclude(
            key__startswith=REVOKED_JWT_PREFIX
        )
        rev_qs = RateLimitBucket.objects.filter(
            key__startswith=REVOKED_JWT_PREFIX,
            window_start__lt=revocation_cutoff,
        )

        rl_deleted = _delete_in_batches(rl_qs, batch_size)
        rev_deleted = _delete_in_batches(rev_qs, batch_size)

        retention_days = max(1, int(getattr(settings, 'FAILED_LOGIN_RETENTION_DAYS', 30)))
        fl_cutoff = now - timedelta(days=retention_days)
        fl_qs = FailedLoginEvent.objects.filter(created_at__lt=fl_cutoff)
        fl_deleted = _delete_in_batches(fl_qs, batch_size, model=FailedLoginEvent, pk_field='id')

        self.stdout.write(
            self.style.SUCCESS(
                f'Cleaned {rl_deleted} expired rate-limit bucket(s), {rev_deleted} expired JWT revocation(s), '
                f'and {fl_deleted} failed login event(s) older than {retention_days} day(s).'
            )
        )
