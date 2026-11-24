import secrets
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from api.models import AuditEntry, User


class Command(BaseCommand):
    help = 'Promote an existing verified, active user to platform admin (is_admin=True, role=admin).'

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True, help='Exact email of the existing user to promote.')

    def handle(self, *args, **options):
        email = str(options.get('email') or '').strip().lower()
        if not email:
            raise CommandError('Email is required.')

        user = User.objects.filter(email=email).first()
        if not user:
            raise CommandError(f'User not found: {email}')
        if not user.is_active:
            raise CommandError(f'Cannot promote inactive user: {email}')
        if not user.verified:
            raise CommandError(f'Cannot promote unverified user: {email}')

        user.is_admin = True
        user.role = 'admin'
        user.save(update_fields=['is_admin', 'role'])

        now = timezone.now()
        AuditEntry.objects.create(
            id=f"AUD-{int(now.timestamp() * 1000)}-{secrets.token_hex(4)}",
            actor='manage_promote_admin',
            action='admin_promoted',
            entity_type='user',
            entity_id=str(user.id),
            extra={'email': user.email},
        )
        self.stdout.write(self.style.SUCCESS(f'Promoted {user.email} to admin.'))
