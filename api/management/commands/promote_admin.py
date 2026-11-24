from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from api.models import User
from api.views import record_audit


class Command(BaseCommand):
    help = 'Promote an existing active, verified user to platform admin (is_admin=True).'

    def add_arguments(self, parser):
        parser.add_argument('--email', required=True, help='Email address of the existing active, verified user.')

    def handle(self, *args, **options):
        email = str(options['email'] or '').strip().lower()
        if not email:
            raise CommandError('Email is required.')

        with transaction.atomic():
            try:
                user = User.objects.select_for_update().get(email=email)
            except User.DoesNotExist:
                raise CommandError(f'No user found with email {email}.')

            if not user.is_active:
                raise CommandError(f'User {email} is inactive and cannot be promoted.')
            if not user.verified:
                raise CommandError(f'User {email} is not email-verified and cannot be promoted.')

            user.is_admin = True
            user.role = 'admin'
            user.save(update_fields=['is_admin', 'role', 'updated_at'])

            record_audit(
                'management:promote_admin',
                'admin_promoted',
                'user',
                str(user.id),
                {'email': user.email},
            )

        self.stdout.write(self.style.SUCCESS(f'Promoted {user.email} to platform admin.'))
