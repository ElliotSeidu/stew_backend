from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from api.models import (
    AnalyticsEvent,
    AuditEntry,
    Compliance,
    FailedLoginEvent,
    Meal,
    Order,
    PayoutBatch,
    PushSubscription,
    RateLimitBucket,
    Review,
    SupportCase,
    User,
    Vendor,
)
from api.views import record_audit


class Command(BaseCommand):
    help = 'Reset non-admin test data between staging test rounds (staging-only; dry-run by default).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apply',
            action='store_true',
            help='Execute deletion (default is dry-run). Must be paired with --i-understand.',
        )
        parser.add_argument(
            '--i-understand',
            action='store_true',
            help='Confirm destructive deletion of non-admin staging data.',
        )

    def handle(self, *args, **options):
        app_env = str(getattr(settings, 'APP_ENV', 'production') or '').strip().lower()
        if app_env != 'staging':
            raise CommandError(
                f"reset_test_data refuses to run when APP_ENV={app_env!r}. Only APP_ENV='staging' is permitted."
            )

        apply_changes = bool(options.get('apply'))
        confirmed = bool(options.get('i_understand'))
        if apply_changes != confirmed:
            raise CommandError('Both --apply and --i-understand are required to execute reset_test_data.')

        admin_qs = User.objects.filter(is_admin=True)
        admin_emails = list(admin_qs.values_list('email', flat=True))
        admin_ids = [str(pk) for pk in admin_qs.values_list('id', flat=True)]

        keep_audit_q = (
            Q(actor__in=admin_emails)
            | Q(actor__startswith='management:')
            | (Q(entity_type='user') & Q(entity_id__in=admin_ids))
        )

        targets = {
            'orders': Order.objects.all(),
            'reviews': Review.objects.all(),
            'meals': Meal.objects.all(),
            'vendors': Vendor.objects.all(),
            'compliance': Compliance.objects.all(),
            'payout_batches': PayoutBatch.objects.all(),
            'support_cases': SupportCase.objects.all(),
            'push_subscriptions': PushSubscription.objects.all(),
            'analytics_events': AnalyticsEvent.objects.all(),
            'rate_limit_buckets': RateLimitBucket.objects.all(),
            'failed_login_events': FailedLoginEvent.objects.all(),
            'non_admin_audit_entries': AuditEntry.objects.exclude(keep_audit_q),
            'non_admin_users': User.objects.filter(is_admin=False),
        }
        counts = {name: qs.count() for name, qs in targets.items()}

        if not apply_changes:
            self.stdout.write(
                f"DRY RUN (APP_ENV=staging, preserving {len(admin_ids)} admin account(s)): {counts}"
            )
            return

        with transaction.atomic():
            for qs in targets.values():
                qs.delete()
            record_audit(
                'management:reset_test_data',
                'staging_data_reset',
                'system',
                'staging',
                {'deleted_counts': counts, 'preserved_admins': len(admin_ids)},
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"APPLIED reset_test_data (preserved {len(admin_ids)} admin account(s)): {counts}"
            )
        )
