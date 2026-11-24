from pathlib import Path
from django.conf import settings
from django.core.management.base import BaseCommand

from api.models import AuditEntry, Compliance


_IDENTITY_KEYS = {
    'iddoc', 'id_doc', 'iddocument', 'id_document', 'idnumber', 'id_number',
    'studentid', 'student_id', 'studentidphoto', 'student_id_photo',
    'studentiddoc', 'student_id_doc', 'studentidnumber', 'student_id_number',
    'nationalid', 'national_id', 'ghanacard', 'ghana_card',
    'passport', 'passportphoto', 'passport_photo',
    'driverslicense', 'drivers_license', 'idphoto', 'id_photo',
    'idfront', 'id_front', 'idback', 'id_back',
}

_IDENTITY_TYPE_KEYWORDS = (
    'student id',
    'national id',
    'ghana card',
    'passport',
    'driver',
    'id card',
    'id doc',
    'identity',
)

_MEDIA_FILENAME_PATTERNS = (
    'id_doc',
    'iddoc',
    'student_id',
    'studentid',
    'ghana_card',
    'ghanacard',
    'national_id',
    'nationalid',
    'passport',
)


def _strip_identity_keys(obj):
    """Recursively remove/redact forbidden identity keys from a dict/list. Returns (cleaned, changed)."""
    if isinstance(obj, dict):
        changed = False
        out = {}
        for k, v in obj.items():
            if str(k).lower() in _IDENTITY_KEYS:
                changed = True
                continue
            cleaned_v, child_changed = _strip_identity_keys(v)
            if child_changed:
                changed = True
            out[k] = cleaned_v
        return out, changed
    if isinstance(obj, list):
        changed = False
        out = []
        for item in obj:
            cleaned_item, item_changed = _strip_identity_keys(item)
            if item_changed:
                changed = True
            out.append(cleaned_item)
        return out, changed
    return obj, False


class Command(BaseCommand):
    help = 'Dry-run (default) or purge (--apply) legacy student ID / identity document references.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--apply',
            action='store_true',
            help='Actually redact AuditEntry metadata, delete matching Compliance rows, and remove matching media files.',
        )

    def handle(self, *args, **options):
        apply_changes = bool(options.get('apply'))

        audit_matches = 0
        for entry in AuditEntry.objects.all():
            cleaned, changed = _strip_identity_keys(entry.extra)
            if changed:
                audit_matches += 1
                if apply_changes:
                    entry.extra = cleaned
                    entry.save(update_fields=['extra'])

        compliance_matches = 0
        for row in Compliance.objects.all():
            ctype = (row.type or '').lower()
            if any(kw in ctype for kw in _IDENTITY_TYPE_KEYWORDS):
                compliance_matches += 1
                if apply_changes:
                    row.delete()

        media_matches = 0
        media_root = getattr(settings, 'MEDIA_ROOT', None)
        if media_root:
            root_path = Path(media_root)
            if root_path.exists() and root_path.is_dir():
                for p in root_path.rglob('*'):
                    if p.is_file():
                        fname = p.name.lower()
                        if any(pat in fname for pat in _MEDIA_FILENAME_PATTERNS):
                            media_matches += 1
                            if apply_changes:
                                p.unlink(missing_ok=True)

        mode = 'APPLIED' if apply_changes else 'DRY-RUN'
        self.stdout.write(
            f"[{mode}] audit_entries_matched={audit_matches} "
            f"compliance_rows_matched={compliance_matches} "
            f"media_files_matched={media_matches}"
        )
