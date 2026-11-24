from django.core.management.base import BaseCommand

from api.models import Order
from api.views import initiate_refund


class Command(BaseCommand):
    help = 'Retry Paystack refunds for cancelled orders stuck in refund_pending (not in a payout batch).'

    def handle(self, *args, **options):
        pending_ids = list(
            Order.objects.filter(
                payment_status='refund_pending',
                payout_batch_id__isnull=True,
            ).values_list('id', flat=True)
        )
        retried = 0
        refunded = 0
        for oid in pending_ids:
            order = initiate_refund(oid, reason='retry_pending', actor_email='manage_retry_pending_refunds')
            retried += 1
            if order.payment_status == 'refunded':
                refunded += 1
        self.stdout.write(
            self.style.SUCCESS(f'Retried {retried} pending refund(s); {refunded} now refunded.')
        )
