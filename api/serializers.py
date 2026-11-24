from datetime import timedelta
from django.conf import settings
from rest_framework import serializers
from api.authentication import is_platform_admin
from api.models import User, Vendor, Meal, Order, Review, Compliance, PayoutBatch, SupportCase, AuditEntry
from api.validators import clean_knust_email, validate_ghana_phone, validate_student_ref_id


class UserSerializer(serializers.ModelSerializer):
    fullName = serializers.CharField(source='full_name')
    referenceId = serializers.CharField(source='reference_id')
    accountType = serializers.CharField(source='account_type')
    isVendor = serializers.BooleanField(source='is_vendor')
    isAdmin = serializers.BooleanField(source='is_admin')
    kitchenName = serializers.CharField(source='kitchen_name', allow_blank=True, required=False)
    area = serializers.CharField(source='hall', allow_blank=True, required=False)
    vendorId = serializers.SerializerMethodField()
    kitchenOpen = serializers.SerializerMethodField()
    vendorActive = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id', 'fullName', 'email', 'role', 'accountType',
            'isVendor', 'isAdmin', 'kitchenName', 'sells',
            'area', 'hall', 'phone', 'referenceId', 'bio',
            'prep', 'payout', 'logo', 'verified', 'vendorId', 'kitchenOpen', 'vendorActive'
        ]
        read_only_fields = fields

    def _get_vendor(self, obj):
        """Returns the first vendor profile, cached per serializer call to avoid N+1."""
        if not hasattr(obj, '_cached_vendor'):
            obj._cached_vendor = obj.vendor_profiles.first() if hasattr(obj, 'vendor_profiles') else None
        return obj._cached_vendor

    def get_vendorId(self, obj):
        vendor = self._get_vendor(obj)
        return vendor.id if vendor else None

    def get_kitchenOpen(self, obj):
        vendor = self._get_vendor(obj)
        return vendor.open if vendor else True

    def get_vendorActive(self, obj):
        vendor = self._get_vendor(obj)
        return vendor.active if vendor else None


class RegisterSerializer(serializers.Serializer):
    fullName = serializers.CharField(required=True, min_length=3)
    email = serializers.CharField(required=True)
    referenceId = serializers.CharField(required=True)
    phone = serializers.CharField(required=True)
    hall = serializers.CharField(required=False, allow_blank=True, default='')
    area = serializers.CharField(required=False, allow_blank=True, default='')
    # Never allow 'admin' during self-registration — prevents privilege escalation
    accountType = serializers.ChoiceField(choices=['customer', 'vendor', 'both'], default='customer')
    kitchenName = serializers.CharField(required=False, allow_blank=True, default='')
    sells = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    password = serializers.CharField(required=True, min_length=8)

    def validate_email(self, value):
        return clean_knust_email(value)

    def validate_referenceId(self, value):
        return validate_student_ref_id(value)

    def validate_phone(self, value):
        return validate_ghana_phone(value)

    def validate_password(self, value):
        if not any(c.isalpha() for c in value) or not any(c.isdigit() for c in value):
            raise serializers.ValidationError('Password must contain both letters and numbers.')
        return value


class VendorSerializer(serializers.ModelSerializer):
    rating = serializers.SerializerMethodField()

    class Meta:
        model = Vendor
        fields = ['id', 'name', 'hall', 'rating', 'reviews', 'open', 'prep', 'bio', 'logo', 'active']
        read_only_fields = fields

    def get_rating(self, obj):
        if (obj.reviews or 0) <= 0 or (obj.rating or 0) <= 0:
            return 0
        return round(obj.rating, 1)


class MealSerializer(serializers.ModelSerializer):
    vendorId = serializers.CharField(source='vendor.id', read_only=True)
    vendorName = serializers.CharField(source='vendor.name', read_only=True)
    hall = serializers.CharField(source='vendor.hall', read_only=True)
    price = serializers.FloatField()
    rating = serializers.SerializerMethodField()
    reviews = serializers.IntegerField(source='vendor.reviews', read_only=True)
    open = serializers.BooleanField(source='vendor.open', read_only=True)

    class Meta:
        model = Meal
        fields = [
            'id', 'vendorId', 'vendorName', 'hall', 'name', 'desc',
            'price', 'cat', 'left', 'kinds', 'image', 'portion',
            'rating', 'reviews', 'open', 'batch', 'on'
        ]
        read_only_fields = fields

    def get_rating(self, obj):
        v = obj.vendor
        if not v or (v.reviews or 0) <= 0 or (v.rating or 0) <= 0:
            return 0
        return round(v.rating, 1)


class OrderSerializer(serializers.ModelSerializer):
    vendorId = serializers.CharField(source='vendor.id', read_only=True)
    vendorName = serializers.CharField(source='vendor_name', read_only=True)
    customer = serializers.CharField(source='customer_name')
    email = serializers.SerializerMethodField()
    subtotal = serializers.FloatField()
    fee = serializers.FloatField()
    total = serializers.FloatField()
    handoffCode = serializers.SerializerMethodField()
    pickupDay = serializers.CharField(source='pickup_day')
    pickupSlot = serializers.CharField(source='pickup_slot')
    prepStage = serializers.CharField(source='prep_stage')
    prepAt = serializers.SerializerMethodField()
    contactNote = serializers.SerializerMethodField()
    orderNote = serializers.SerializerMethodField()
    phone = serializers.SerializerMethodField()
    meetup = serializers.SerializerMethodField()
    messages = serializers.SerializerMethodField()
    collectedVia = serializers.CharField(source='collected_via', allow_blank=True, read_only=True)
    payoutBatchId = serializers.CharField(source='payout_batch_id', allow_null=True, read_only=True)
    payment = serializers.SerializerMethodField()
    settlement = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    createdAt = serializers.SerializerMethodField()
    collectedAt = serializers.SerializerMethodField()
    cancelledAt = serializers.SerializerMethodField()
    reviewed = serializers.SerializerMethodField()

    class Meta:
        model = Order
        fields = [
            'id', 'vendorId', 'vendorName', 'customer', 'email', 'phone', 'area',
            'contactNote', 'lines', 'subtotal', 'fee', 'total', 'orderNote',
            'handoffCode', 'pickupDay', 'pickupSlot', 'payment', 'settlement',
            'prepStage', 'prepAt', 'status', 'meetup', 'messages', 'createdAt',
            'collectedAt', 'collectedVia', 'cancelledAt', 'payoutBatchId', 'reviewed'
        ]
        read_only_fields = fields

    def _is_owner_or_admin(self, obj) -> bool:
        request = self.context.get('request')
        if not (request and hasattr(request, 'user') and request.user.is_authenticated):
            return False
        return bool(
            (obj.customer_id and str(obj.customer_id) == str(request.user.id))
            or obj.email == request.user.email
            or is_platform_admin(request.user)
        )

    def _is_admin_viewer(self) -> bool:
        request = self.context.get('request')
        return bool(request and hasattr(request, 'user') and request.user.is_authenticated and is_platform_admin(request.user))

    def get_email(self, obj):
        return obj.email if self._is_owner_or_admin(obj) else None

    def get_phone(self, obj):
        return obj.phone if self._is_owner_or_admin(obj) else None

    def get_contactNote(self, obj):
        raw = obj.contact_note or ''
        if self._is_admin_viewer():
            return raw
        from api.security import mask_phone_numbers
        return mask_phone_numbers(raw)[0]

    def get_orderNote(self, obj):
        raw = obj.order_note or ''
        if self._is_admin_viewer():
            return raw
        from api.security import mask_phone_numbers
        return mask_phone_numbers(raw)[0]

    def get_meetup(self, obj):
        if not obj.meetup or self._is_admin_viewer():
            return obj.meetup
        if not isinstance(obj.meetup, dict):
            return obj.meetup
        from api.security import mask_phone_numbers
        out = {}
        for k, v in obj.meetup.items():
            out[k] = mask_phone_numbers(v)[0] if isinstance(v, str) else v
        return out

    def get_messages(self, obj):
        msgs = obj.messages or []
        if not msgs or self._is_admin_viewer():
            return msgs
        from api.security import mask_phone_numbers
        out = []
        for m in msgs:
            if isinstance(m, dict):
                copy_m = dict(m)
                if isinstance(copy_m.get('text'), str):
                    copy_m['text'] = mask_phone_numbers(copy_m['text'])[0]
                out.append(copy_m)
            else:
                out.append(m)
        return out

    def get_prepAt(self, obj):
        return {k: v for k, v in (obj.prep_at or {}).items() if not str(k).startswith('_')}

    def get_reviewed(self, obj):
        # Use annotation from orders_view queryset when available (avoids N+1 on list views)
        if hasattr(obj, '_has_review'):
            return bool(obj._has_review)
        return Review.objects.filter(order_id=obj.id).exists()

    def get_handoffCode(self, obj):
        if obj.prep_stage == 'collected' or obj.collected_at or obj.cancelled_at:
            return None
        return obj.handoff_code if self._is_owner_or_admin(obj) else None

    def get_payment(self, obj):
        paid_at_ts = int(obj.paid_at.timestamp() * 1000) if obj.paid_at else None
        ttl_mins = max(1, int(getattr(settings, 'UNPAID_ORDER_TTL_MINUTES', 30)))
        expires_at_ts = (
            int((obj.created_at + timedelta(minutes=ttl_mins)).timestamp() * 1000)
            if (obj.payment_status == 'pending' and not obj.cancelled_at and not obj.paid_at and obj.created_at)
            else None
        )
        return {
            'status': obj.payment_status,
            'provider': obj.payment_provider,
            'reference': obj.payment_reference if self._is_owner_or_admin(obj) else None,
            'paidAt': paid_at_ts,
            'expiresAt': expires_at_ts,
        }

    def get_settlement(self, obj):
        released_at_ts = int(obj.settlement_released_at.timestamp() * 1000) if obj.settlement_released_at else None
        return {
            'status': obj.settlement_status,
            'releasedAt': released_at_ts,
            'net': round(float(obj.settlement_net or 0), 2),
        }

    def get_status(self, obj):
        if obj.cancelled_at:
            return 'cancelled'
        if obj.prep_stage == 'collected' or obj.collected_at:
            return 'delivered'
        active_stages = ['accepted', 'shopping', 'cooking', 'packing']
        return 'preparing' if obj.prep_stage in active_stages else 'ready'

    def get_createdAt(self, obj):
        return int(obj.created_at.timestamp() * 1000)

    def get_collectedAt(self, obj):
        return int(obj.collected_at.timestamp() * 1000) if obj.collected_at else None

    def get_cancelledAt(self, obj):
        return int(obj.cancelled_at.timestamp() * 1000) if obj.cancelled_at else None


class ReviewSerializer(serializers.ModelSerializer):
    orderId = serializers.CharField(source='order_id')
    vendorId = serializers.CharField(source='vendor.id', read_only=True)
    vendorName = serializers.CharField(source='vendor_name')
    moderationStatus = serializers.CharField(source='moderation_status')
    moderationReason = serializers.CharField(source='moderation_reason')
    createdAt = serializers.SerializerMethodField()

    class Meta:
        model = Review
        fields = [
            'id', 'orderId', 'vendorId', 'vendorName', 'rating',
            'tags', 'text', 'moderationStatus', 'moderationReason', 'createdAt'
        ]
        read_only_fields = fields

    def get_createdAt(self, obj):
        return int(obj.created_at.timestamp() * 1000)


class ComplianceSerializer(serializers.ModelSerializer):
    vendorId = serializers.CharField(source='vendor_id')
    vendorName = serializers.CharField(source='vendor_name', allow_blank=True)
    issuedAt = serializers.CharField(source='issued_at', allow_blank=True)
    expiresAt = serializers.CharField(source='expires_at', allow_blank=True)
    reviewedBy = serializers.CharField(source='reviewed_by', allow_blank=True)
    updatedAt = serializers.SerializerMethodField()

    class Meta:
        model = Compliance
        fields = ['vendorId', 'vendorName', 'type', 'number', 'issuedAt', 'expiresAt', 'reviewedBy', 'updatedAt']
        read_only_fields = fields

    def get_updatedAt(self, obj):
        return int(obj.updated_at.timestamp() * 1000)


class PayoutBatchSerializer(serializers.ModelSerializer):
    amount = serializers.FloatField()
    orderCount = serializers.IntegerField(source='order_count')
    periodStart = serializers.SerializerMethodField()
    periodEnd = serializers.SerializerMethodField()
    providerReference = serializers.CharField(source='provider_reference')
    createdAt = serializers.SerializerMethodField()
    paidAt = serializers.SerializerMethodField()

    class Meta:
        model = PayoutBatch
        fields = [
            'id', 'amount', 'currency', 'status', 'orderCount',
            'periodStart', 'periodEnd', 'provider', 'providerReference',
            'createdAt', 'paidAt'
        ]
        read_only_fields = fields

    def get_periodStart(self, obj):
        return int(obj.period_start.timestamp() * 1000) if obj.period_start else None

    def get_periodEnd(self, obj):
        return int(obj.period_end.timestamp() * 1000) if obj.period_end else None

    def get_createdAt(self, obj):
        return int(obj.created_at.timestamp() * 1000)

    def get_paidAt(self, obj):
        return int(obj.paid_at.timestamp() * 1000) if obj.paid_at else None


class SupportCaseSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source='code', read_only=True)
    orderId = serializers.CharField(source='order', read_only=True)
    description = serializers.CharField(source='note', read_only=True)
    createdAt = serializers.SerializerMethodField()

    class Meta:
        model = SupportCase
        fields = ['id', 'code', 'type', 'order', 'orderId', 'vendor', 'priority', 'note', 'description', 'createdAt']
        read_only_fields = fields

    def get_createdAt(self, obj):
        return int(obj.created_at.timestamp() * 1000)


class AuditEntrySerializer(serializers.ModelSerializer):
    entityType = serializers.CharField(source='entity_type')
    entityId = serializers.CharField(source='entity_id')
    at = serializers.SerializerMethodField()

    class Meta:
        model = AuditEntry
        fields = ['id', 'actor', 'action', 'entityType', 'entityId', 'extra', 'at']
        read_only_fields = fields

    def get_at(self, obj):
        return int(obj.at.timestamp() * 1000)


class AdminUserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField()
    accountType = serializers.CharField(source='account_type', read_only=True)
    active = serializers.BooleanField(source='is_active')
    isAdmin = serializers.BooleanField(source='is_admin', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'role', 'accountType', 'isAdmin', 'active', 'verified', 'hall']
        read_only_fields = fields

    def get_name(self, obj):
        return obj.full_name or obj.email.split('@')[0]
