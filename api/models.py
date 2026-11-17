from decimal import Decimal
import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from api.validators import clean_knust_email


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email address is mandatory.')
        # Clean and validate that email is strictly a KNUST student email
        clean_email = clean_knust_email(email)
        user = self.model(email=clean_email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)
        extra_fields.setdefault('role', 'admin')
        extra_fields.setdefault('account_type', 'admin')
        extra_fields.setdefault('verified', True)
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    id = models.CharField(max_length=64, primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    full_name = models.CharField(max_length=150, default='')
    reference_id = models.CharField(max_length=16, blank=True, default='')
    phone = models.CharField(max_length=32, blank=True, default='')
    hall = models.CharField(max_length=100, blank=True, default='')
    role = models.CharField(max_length=32, default='customer')  # 'customer', 'vendor', 'admin'
    account_type = models.CharField(max_length=32, default='customer')  # 'customer', 'vendor', 'both', 'admin'
    kitchen_name = models.CharField(max_length=150, blank=True, default='')
    sells = models.JSONField(default=list, blank=True)
    bio = models.TextField(blank=True, default='')
    prep = models.IntegerField(default=6)
    payout = models.CharField(max_length=32, blank=True, default='')
    logo = models.TextField(blank=True, default='')
    
    is_vendor = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    verified = models.BooleanField(default=False)
    
    verification_code_hash = models.CharField(max_length=128, blank=True, default='')
    verification_code_expires = models.DateTimeField(null=True, blank=True)
    login_code_hash = models.CharField(max_length=128, blank=True, default='')
    login_code_expires = models.DateTimeField(null=True, blank=True)
    reset_code_hash = models.CharField(max_length=128, blank=True, default='')
    reset_code_expires = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.email} ({self.role})"

    @property
    def area(self):
        return self.hall

    @area.setter
    def area(self, value):
        self.hall = value or ''


class Vendor(models.Model):
    id = models.CharField(max_length=64, primary_key=True)  # e.g. 'v1', 'v2', etc.
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='vendor_profiles')
    name = models.CharField(max_length=150)
    hall = models.CharField(max_length=100)
    rating = models.FloatField(default=0.0)
    reviews = models.IntegerField(default=0)
    open = models.BooleanField(default=True)
    prep = models.IntegerField(default=6)
    bio = models.TextField(blank=True, default='')
    logo = models.TextField(blank=True, default='')
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']

    def __str__(self):
        return self.name


class Meal(models.Model):
    id = models.CharField(max_length=64, primary_key=True)  # e.g. 'm1', 'm2', etc.
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='meals')
    name = models.CharField(max_length=150)
    desc = models.TextField(blank=True, default='')
    price = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.50'))
    cat = models.CharField(max_length=64, default='Soups')
    left = models.IntegerField(default=10)
    kinds = models.JSONField(default=list, blank=True)
    image = models.TextField(blank=True, default='')
    portion = models.CharField(max_length=100, default='Single portion')
    on = models.BooleanField(default=True)
    batch = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        constraints = [
            models.CheckConstraint(condition=models.Q(price__gte=Decimal('0.50')), name='meal_price_gte_0_50'),
            models.CheckConstraint(condition=models.Q(left__gte=0), name='meal_left_non_negative'),
        ]

    def __str__(self):
        return f"{self.name} - {self.vendor.name}"


class Order(models.Model):
    id = models.CharField(max_length=64, primary_key=True)  # e.g. 'STW-4821'
    customer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='customer_orders')
    customer_name = models.CharField(max_length=150, default='')
    email = models.EmailField()
    phone = models.CharField(max_length=32)
    area = models.CharField(max_length=100)
    contact_note = models.CharField(max_length=200, blank=True, default='')
    vendor = models.ForeignKey(Vendor, on_delete=models.SET_NULL, null=True, blank=True, related_name='vendor_orders')
    vendor_name = models.CharField(max_length=150)
    lines = models.JSONField(default=list)
    subtotal = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    fee = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    total = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    order_note = models.TextField(blank=True, default='')
    handoff_code = models.CharField(max_length=16, blank=True, default='')
    pickup_day = models.CharField(max_length=32)
    pickup_slot = models.CharField(max_length=32, default='afternoon')
    prep_stage = models.CharField(max_length=32, default='accepted')
    prep_at = models.JSONField(default=dict, blank=True)
    
    payment_status = models.CharField(max_length=32, default='pending')  # pending, paid, released, refund_pending, refunded, cancelled
    payment_provider = models.CharField(max_length=32, default='paystack')
    payment_reference = models.CharField(max_length=128, null=True, blank=True, unique=True, db_index=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    
    settlement_status = models.CharField(max_length=32, default='pending')  # pending, released
    settlement_released_at = models.DateTimeField(null=True, blank=True)
    settlement_net = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    
    meetup = models.JSONField(null=True, blank=True)
    messages = models.JSONField(default=list, blank=True)
    
    collected_at = models.DateTimeField(null=True, blank=True)
    collected_via = models.CharField(max_length=64, blank=True, default='')
    collection_nudged_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    
    payout_batch_id = models.CharField(max_length=64, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.CheckConstraint(condition=models.Q(subtotal__gte=Decimal('0.00')), name='order_subtotal_non_negative'),
            models.CheckConstraint(condition=models.Q(fee__gte=Decimal('0.00')), name='order_fee_non_negative'),
            models.CheckConstraint(condition=models.Q(total__gte=Decimal('0.00')), name='order_total_non_negative'),
            models.CheckConstraint(condition=models.Q(settlement_net__gte=Decimal('0.00')), name='order_settlement_net_non_negative'),
        ]

    def __str__(self):
        return f"{self.id} ({self.vendor_name}) - {self.total} GHS"


class Review(models.Model):
    order_id = models.CharField(max_length=64, unique=True)
    vendor = models.ForeignKey(Vendor, on_delete=models.CASCADE, related_name='reviews_list')
    vendor_name = models.CharField(max_length=150, blank=True, default='')
    customer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='reviews')
    rating = models.IntegerField(default=5)
    tags = models.JSONField(default=list, blank=True)
    text = models.TextField(blank=True, default='')
    moderation_status = models.CharField(max_length=32, default='pending')  # pending, visible, hidden
    moderation_reason = models.TextField(blank=True, default='')
    moderated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.CheckConstraint(condition=models.Q(rating__gte=1) & models.Q(rating__lte=5), name='review_rating_1_to_5'),
        ]


class Compliance(models.Model):
    vendor_id = models.CharField(max_length=150, unique=True)  # email or vendor ID
    vendor_name = models.CharField(max_length=150, blank=True, default='')
    type = models.CharField(max_length=100, default='FDA food hygiene permit')
    number = models.CharField(max_length=100, blank=True, default='')
    issued_at = models.CharField(max_length=64, blank=True, default='')
    expires_at = models.CharField(max_length=64, blank=True, default='')
    reviewed_by = models.CharField(max_length=150, blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']


class PayoutBatch(models.Model):
    id = models.CharField(max_length=64, primary_key=True)  # e.g. PAY-1001
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))
    currency = models.CharField(max_length=16, default='GHS')
    status = models.CharField(max_length=32, default='paid')
    order_count = models.IntegerField(default=0)
    period_start = models.DateTimeField(null=True, blank=True)
    period_end = models.DateTimeField(null=True, blank=True)
    provider = models.CharField(max_length=32, default='paystack')
    provider_reference = models.CharField(max_length=128, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        constraints = [
            models.CheckConstraint(condition=models.Q(amount__gte=Decimal('0.00')), name='payout_batch_amount_non_negative'),
        ]


class SupportCase(models.Model):
    code = models.CharField(max_length=64, primary_key=True)  # CASE-XXXX
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='support_cases')
    type = models.CharField(max_length=64)
    order = models.CharField(max_length=64, blank=True, default='')
    vendor = models.CharField(max_length=150, blank=True, default='')
    priority = models.CharField(max_length=32, default='normal')
    note = models.TextField(blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']


class PushSubscription(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name='push_subscriptions')
    endpoint = models.TextField(unique=True)
    keys = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class AuditEntry(models.Model):
    id = models.CharField(max_length=64, primary_key=True)
    actor = models.CharField(max_length=150)
    action = models.CharField(max_length=100)
    entity_type = models.CharField(max_length=64)
    entity_id = models.CharField(max_length=64)
    extra = models.JSONField(default=dict, blank=True)
    at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-at']


class AnalyticsEvent(models.Model):
    event = models.CharField(max_length=100)
    payload = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
