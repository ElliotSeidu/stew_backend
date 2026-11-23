from datetime import timedelta
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone as dj_timezone

from api.models import Order
from api.views import _restore_order_stock, record_audit


class Command(BaseCommand):
    help = 'Cancels expired unpaid pending orders under row locks and restores reserved stock idempotently.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--ttl-minutes',
            type=int,
            default=None,
            help='Override settings.UNPAID_ORDER_TTL_MINUTES for this run (0 expires any unpaid pending order immediately).',
        )
        parser.add_argument(
            '--batch-size',
            type=int,
            default=500,
            help='Maximum candidate rows processed in this run (default: 500).',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Report matching expired unpaid orders without modifying records.',
        )

    def handle(self, *args, **options):
        raw_ttl = options.get('ttl_minutes')
        if raw_ttl is None:
            ttl_minutes = max(1, int(getattr(settings, 'UNPAID_ORDER_TTL_MINUTES', 30)))
        else:
            ttl_minutes = max(0, int(raw_ttl))
        batch_size = max(1, int(options.get('batch_size') or 500))
        dry_run = bool(options.get('dry_run'))

        cutoff = dj_timezone.now() - timedelta(minutes=ttl_minutes)
        candidate_ids = list(
            Order.objects.filter(
                cancelled_at__isnull=True,
                paid_at__isnull=True,
                payment_status='pending',
                created_at__lte=cutoff,
            )
            .order_by('created_at', 'id')
            .values_list('id', flat=True)[:batch_size]
        )

        if dry_run:
            self.stdout.write(
                f'[dry-run] Would evaluate {len(candidate_ids)} unpaid order(s) older than {ttl_minutes}m.'
            )
            return

        expired_count = 0
        for oid in candidate_ids:
            now = dj_timezone.now()
            row_cutoff = now - timedelta(minutes=ttl_minutes)
            with transaction.atomic():
                locked = Order.objects.select_for_update().filter(pk=oid).first()
                if not locked:
                    continue
                if (
                    locked.cancelled_at is not None
                    or locked.is_vendor_visible
                    or locked.payment_status != 'pending'
                    or (locked.created_at and locked.created_at > row_cutoff)
                ):
                    continue
                prep_at = dict(locked.prep_at or {})
                prep_at['_expired'] = True
                locked.cancelled_at = now
                locked.payment_status = 'cancelled'
                locked.prep_at = prep_at
                locked.save(update_fields=['cancelled_at', 'payment_status', 'prep_at'])
                _restore_order_stock(locked)
                record_audit(
                    'system',
                    'order_expired_unpaid',
                    'order',
                    locked.id,
                    {'ttlMinutes': ttl_minutes},
                )
                expired_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                f'Expired {expired_count} unpaid order(s) older than {ttl_minutes}m.'
            )
        )
