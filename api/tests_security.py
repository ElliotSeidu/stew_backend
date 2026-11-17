"""
Security regression tests for STEW API.

Each test class demonstrates a vulnerability/loophole before remediation and
stays as a regression guard after the fix.
"""
import hashlib
import hmac
import json
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch
from django.conf import settings
from django.db import IntegrityError, connection, connections, models, transaction
from django.test import TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import User, Vendor, Meal, Order, PayoutBatch, Review, SupportCase
from api.security import generate_jwt_token, hash_token, _RATE_LIMIT_CACHE


class VendorGateSecurityTests(TestCase):
    """
    FINDING-01: Unverified, pending, and suspended (active=False) vendors must
    never be able to appear in public listings, self-reactivate, mutate menus,
    process/complete orders, or be swept into payout batches.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='sec.admin@st.knust.edu.gh',
            password='AdminPassword123',
            full_name='Security Admin',
        )
        cls.admin_token = generate_jwt_token(cls.admin)

        cls.student = User.objects.create_user(
            email='sec.student@st.knust.edu.gh',
            password='Password123',
            full_name='Security Student',
            reference_id='20880001',
            phone='0248000001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.student_token = generate_jwt_token(cls.student)

        cls.unverified_vendor = User.objects.create_user(
            email='sec.unver.vendor@st.knust.edu.gh',
            password='Password123',
            full_name='Unverified Chef',
            reference_id='20880002',
            phone='0248000002',
            hall='Queens Hall',
            verified=False,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Unverified Pot',
        )
        cls.unverified_vendor_profile = Vendor.objects.create(
            id='v_sec_unv',
            user=cls.unverified_vendor,
            name='Unverified Pot',
            hall='Queens Hall',
            open=True,
            active=True,
        )
        cls.unverified_token = generate_jwt_token(cls.unverified_vendor)

        cls.suspended_vendor_user = User.objects.create_user(
            email='sec.susp.vendor@st.knust.edu.gh',
            password='Password123',
            full_name='Suspended Chef',
            reference_id='20880003',
            phone='0248000003',
            hall='Katanga Hall',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Suspended Pot',
        )
        cls.suspended_vendor = Vendor.objects.create(
            id='v_sec_susp',
            user=cls.suspended_vendor_user,
            name='Suspended Pot',
            hall='Katanga Hall',
            open=True,
            active=False,
        )
        cls.suspended_meal = Meal.objects.create(
            id='m_sec_susp',
            vendor=cls.suspended_vendor,
            name='Suspended Jollof',
            price=35.0,
            cat='Rice & stews',
            left=10,
            on=True,
        )
        cls.suspended_order = Order.objects.create(
            id='STW-SUSP1',
            customer=cls.student,
            customer_name=cls.student.full_name,
            email=cls.student.email,
            phone=cls.student.phone,
            area='Unity Hall (Conti)',
            vendor=cls.suspended_vendor,
            vendor_name=cls.suspended_vendor.name,
            lines=[{'mealId': cls.suspended_meal.id, 'name': cls.suspended_meal.name, 'price': 35.0, 'qty': 1}],
            subtotal=35.0,
            fee=1.75,
            total=36.75,
            pickup_day='2026-11-20',
            handoff_code='654321',
            prep_stage='accepted',
            payment_status='paid',
            settlement_status='pending',
            paid_at=timezone.now(),
        )
        cls.suspended_token = generate_jwt_token(cls.suspended_vendor_user)

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_signup_unverified_vendor_starts_inactive_and_hidden(self):
        res = self.client.post('/api/auth/register/', {
            'fullName': 'Pending Signup Chef',
            'email': 'pending.chef@st.knust.edu.gh',
            'referenceId': '20880010',
            'phone': '0248000010',
            'accountType': 'vendor',
            'kitchenName': 'Pending Campus Kitchen',
            'hall': 'Queens Hall',
            'sells': ['Waakye'],
            'password': 'Password123',
        }, format='json')
        self.assertEqual(res.status_code, 201)
        v = Vendor.objects.get(name='Pending Campus Kitchen')
        self.assertFalse(v.active)
        self.assertFalse(v.open)

        list_res = self.client.get('/api/vendors/')
        self.assertEqual(list_res.status_code, 200)
        self.assertNotIn(v.id, [row['id'] for row in list_res.data])

    def test_unverified_vendor_cannot_use_vendor_endpoints(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.unverified_token}')
        meal_res = self.client.post('/api/meals/', {
            'name': 'Unverified Dish',
            'price': 25,
            'stock': 5,
            'cat': 'Soups',
        }, format='json')
        self.assertIn(meal_res.status_code, (401, 403))

        apply_res = self.client.post('/api/vendor/apply/', {
            'kitchen': 'Unverified Override',
            'hall': 'Queens Hall',
        }, format='json')
        self.assertIn(apply_res.status_code, (401, 403))

        payout_res = self.client.get('/api/payouts/')
        self.assertIn(payout_res.status_code, (401, 403))

    def test_suspended_vendor_cannot_self_reactivate_or_appear_publicly(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.suspended_token}')
        apply_res = self.client.post('/api/vendor/apply/', {
            'kitchen': 'Self Reactivated Pot',
            'hall': 'Katanga Hall',
            'payout': '0248000003',
        }, format='json')
        self.assertEqual(apply_res.status_code, 403)
        self.suspended_vendor.refresh_from_db()
        self.assertFalse(self.suspended_vendor.active)

        # Public detail endpoint must hide suspended vendor
        self.client.credentials()
        detail_res = self.client.get(f'/api/vendors/{self.suspended_vendor.id}/')
        self.assertEqual(detail_res.status_code, 404)

        meals_res = self.client.get('/api/meals/')
        self.assertEqual(meals_res.status_code, 200)
        self.assertNotIn(self.suspended_meal.id, [m['id'] for m in meals_res.data])

    def test_suspended_vendor_cannot_mutate_meals(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.suspended_token}')
        create_res = self.client.post('/api/meals/', {
            'name': 'Suspended New Dish',
            'price': 30,
            'stock': 4,
            'cat': 'Soups',
        }, format='json')
        self.assertEqual(create_res.status_code, 403)

        edit_res = self.client.patch(f'/api/meals/{self.suspended_meal.id}/', {'price': 99}, format='json')
        self.assertEqual(edit_res.status_code, 403)

        del_res = self.client.delete(f'/api/meals/{self.suspended_meal.id}/')
        self.assertEqual(del_res.status_code, 403)

    def test_suspended_vendor_cannot_advance_or_complete_orders_and_excluded_from_payout_batch(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.suspended_token}')
        prep_res = self.client.post(f'/api/orders/{self.suspended_order.id}/prep/', {'stage': 'cooking'}, format='json')
        self.assertEqual(prep_res.status_code, 403)

        nudge_res = self.client.post(f'/api/orders/{self.suspended_order.id}/collection-nudge/', format='json')
        self.assertEqual(nudge_res.status_code, 403)

        complete_res = self.client.post(
            f'/api/orders/{self.suspended_order.id}/complete/',
            {'code': '654321'},
            format='json',
        )
        self.assertEqual(complete_res.status_code, 403)
        self.suspended_order.refresh_from_db()
        self.assertIsNone(self.suspended_order.collected_at)
        self.assertEqual(self.suspended_order.settlement_status, 'pending')

        # Even if a suspended vendor has a released order, creating a payout batch excludes suspended kitchens
        self.suspended_order.settlement_status = 'released'
        self.suspended_order.payment_status = 'released'
        self.suspended_order.collected_at = timezone.now()
        self.suspended_order.prep_stage = 'collected'
        self.suspended_order.save()

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        batch_res = self.client.post('/api/payouts/batches/', format='json')
        self.assertEqual(batch_res.status_code, 400)
        self.suspended_order.refresh_from_db()
        self.assertIsNone(self.suspended_order.payout_batch_id)

    def test_inactive_or_suspended_vendor_owner_can_read_own_vendor_detail_and_compliance_but_public_cannot(self):
        # Owner of inactive/pending vendor can still inspect own vendor status, profile, and compliance
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.suspended_token}')
        me_res = self.client.get('/api/auth/me/')
        self.assertEqual(me_res.status_code, 200)

        own_detail = self.client.get(f'/api/vendors/{self.suspended_vendor.id}/')
        self.assertEqual(own_detail.status_code, 200, own_detail.data)
        self.assertEqual(own_detail.data['id'], self.suspended_vendor.id)

        comp_get = self.client.get('/api/vendor/compliance/')
        self.assertEqual(comp_get.status_code, 200)
        comp_post = self.client.post('/api/vendor/compliance/', {
            'type': 'FDA food hygiene permit',
            'number': 'FDA-KNUST-991',
            'issuedAt': '2026-01-01',
            'expiresAt': '2027-01-01',
        }, format='json')
        self.assertEqual(comp_post.status_code, 200)

        # Other students and anonymous callers still get 404 for inactive kitchens
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        other_detail = self.client.get(f'/api/vendors/{self.suspended_vendor.id}/')
        self.assertEqual(other_detail.status_code, 404)

    def test_suspended_vendor_cannot_self_reactivate_via_vendor_activate_or_verify_email(self):
        from api.models import AuditEntry
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.suspended_token}')
        act_res = self.client.post('/api/vendor/activate/', {}, format='json')
        self.assertEqual(act_res.status_code, 403)

        # Simulate admin suspension audit trail followed by OTP re-verification
        Vendor.objects.filter(id=self.suspended_vendor.id).update(active=False, open=False)
        AuditEntry.objects.create(
            actor=self.admin.email,
            action='admin_vendor_updated',
            entity_type='vendor',
            entity_id=self.suspended_vendor.id,
            extra={'active': False, 'open': False},
        )
        self.suspended_vendor_user.verified = False
        self.suspended_vendor_user.verification_code_hash = hash_token('445566')
        self.suspended_vendor_user.verification_code_expires = timezone.now() + timedelta(minutes=10)
        self.suspended_vendor_user.save(update_fields=[
            'verified', 'verification_code_hash', 'verification_code_expires',
        ])

        self.client.credentials()
        ver_res = self.client.post('/api/auth/verify-email/', {
            'email': self.suspended_vendor_user.email,
            'code': '445566',
        }, format='json')
        self.assertEqual(ver_res.status_code, 200, ver_res.data)
        self.suspended_vendor.refresh_from_db()
        self.assertFalse(self.suspended_vendor.active)
        self.assertFalse(self.suspended_vendor.open)


class OrderStateAndConcurrencySecurityTests(TestCase):
    """
    FINDING-02 & FINDING-03: Terminal orders (cancelled/collected) and unpaid
    orders cannot regress in prep stage or accept meetup/message mutations;
    support cases reject duplicates on refunded orders and restore stock when
    refunding an uncollected order.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='ord.admin@st.knust.edu.gh',
            password='AdminPassword123',
            full_name='Order Admin',
        )
        cls.admin_token = generate_jwt_token(cls.admin)

        cls.student = User.objects.create_user(
            email='ord.student@st.knust.edu.gh',
            password='Password123',
            full_name='Order Student',
            reference_id='20881001',
            phone='0248100001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.student_token = generate_jwt_token(cls.student)

        cls.vendor_user = User.objects.create_user(
            email='ord.vendor@st.knust.edu.gh',
            password='Password123',
            full_name='Order Chef',
            reference_id='20881002',
            phone='0248100002',
            hall='Unity Hall (Conti)',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='State Safe Kitchen',
        )
        cls.vendor = Vendor.objects.create(
            id='v_sec_ord',
            user=cls.vendor_user,
            name='State Safe Kitchen',
            hall='Unity Hall (Conti)',
            open=True,
            active=True,
        )
        cls.vendor_token = generate_jwt_token(cls.vendor_user)
        cls.meal = Meal.objects.create(
            id='m_sec_ord',
            vendor=cls.vendor,
            name='State Banku',
            price=30.0,
            cat='Banku',
            left=10,
            on=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_collected_and_unpaid_orders_cannot_change_prep_stage(self):
        unpaid = Order.objects.create(
            id='STW-UNP9',
            customer=self.student,
            customer_name=self.student.full_name,
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 30.0, 'qty': 1}],
            subtotal=30.0,
            fee=1.5,
            total=31.5,
            pickup_day='2026-11-20',
            prep_stage='accepted',
            payment_status='pending',
            settlement_status='pending',
        )
        collected = Order.objects.create(
            id='STW-COL9',
            customer=self.student,
            customer_name=self.student.full_name,
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 30.0, 'qty': 1}],
            subtotal=30.0,
            fee=1.5,
            total=31.5,
            pickup_day='2026-11-20',
            prep_stage='collected',
            collected_at=timezone.now(),
            payment_status='released',
            settlement_status='released',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        unpaid_res = self.client.post(f'/api/orders/{unpaid.id}/prep/', {'stage': 'ready'}, format='json')
        self.assertEqual(unpaid_res.status_code, 400)

        collected_res = self.client.post(f'/api/orders/{collected.id}/prep/', {'stage': 'cooking'}, format='json')
        self.assertEqual(collected_res.status_code, 400)
        collected.refresh_from_db()
        self.assertEqual(collected.prep_stage, 'collected')

    def test_terminal_orders_block_meetup_and_message_mutations(self):
        cancelled = Order.objects.create(
            id='STW-CAN9',
            customer=self.student,
            customer_name=self.student.full_name,
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 30.0, 'qty': 1}],
            subtotal=30.0,
            fee=1.5,
            total=31.5,
            pickup_day='2026-11-20',
            prep_stage='accepted',
            payment_status='refunded',
            cancelled_at=timezone.now(),
            meetup={'place': 'Old spot', 'confirmedBy': ['student'], 'agreed': False},
        )
        collected = Order.objects.create(
            id='STW-COL8',
            customer=self.student,
            customer_name=self.student.full_name,
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 30.0, 'qty': 1}],
            subtotal=30.0,
            fee=1.5,
            total=31.5,
            pickup_day='2026-11-20',
            prep_stage='collected',
            collected_at=timezone.now(),
            payment_status='released',
            settlement_status='released',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        for o in (cancelled, collected):
            self.assertEqual(
                self.client.post(f'/api/orders/{o.id}/meetup/propose/', {'place': 'Tech Junction'}, format='json').status_code,
                400,
            )
            self.assertEqual(
                self.client.post(f'/api/orders/{o.id}/messages/', {'text': 'Late msg'}, format='json').status_code,
                400,
            )
        self.assertEqual(self.client.post(f'/api/orders/{cancelled.id}/meetup/confirm/', format='json').status_code, 400)
        self.assertEqual(self.client.post(f'/api/orders/{cancelled.id}/meetup/decline/', format='json').status_code, 400)

    def test_support_case_duplicate_and_refund_stock_restoration(self):
        # Student places an order for 3 portions (stock drops 10 -> 7)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        order_res = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 3}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-11-20',
        }, format='json')
        self.assertEqual(order_res.status_code, 201)
        order_id = order_res.data['id']
        Order.objects.filter(pk=order_id).update(payment_status='paid', paid_at=timezone.now())
        self.meal.refresh_from_db()
        self.assertEqual(self.meal.left, 7)

        c1 = self.client.post('/api/support/cases/', {
            'type': 'missing',
            'orderId': order_id,
            'note': 'Order stuck',
        }, format='json')
        self.assertEqual(c1.status_code, 201)

        # Duplicate open case by same user for same order must be blocked
        c2 = self.client.post('/api/support/cases/', {
            'type': 'missing',
            'orderId': order_id,
            'note': 'Duplicate request',
        }, format='json')
        self.assertEqual(c2.status_code, 400)

        # Admin refunding uncollected order must restore Meal.left (7 -> 10)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.post(f"/api/support/cases/{c1.data['code']}/resolve/", {'action': 'refund'}, format='json')
        self.assertEqual(res.status_code, 200)
        self.meal.refresh_from_db()
        self.assertEqual(self.meal.left, 10)

        # New case after refund on already-refunded order must be blocked
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        c3 = self.client.post('/api/support/cases/', {
            'type': 'missing',
            'orderId': order_id,
            'note': 'Second refund attempt',
        }, format='json')
        self.assertEqual(c3.status_code, 400)


class AuthAndOtpSecurityTests(TestCase):
    """
    FINDING-04 & FINDING-05:
      - Unverified users must be rejected by JWTAuthentication and login-code flow.
      - OTP rate-limit lockout must burn stored OTP hashes so codes cannot be
        brute-forced across successive 10-minute windows.
      - Verified student reference IDs must be unique across registrations.
    """

    @classmethod
    def setUpTestData(cls):
        cls.verified_student = User.objects.create_user(
            email='auth.ver@st.knust.edu.gh',
            password='Password123',
            full_name='Verified Auth Student',
            reference_id='20882001',
            phone='0248200001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.unverified_student = User.objects.create_user(
            email='auth.unver@st.knust.edu.gh',
            password='Password123',
            full_name='Unverified Auth Student',
            reference_id='20882002',
            phone='0248200002',
            hall='Queens Hall',
            verified=False,
        )
        cls.unverified_token = generate_jwt_token(cls.unverified_student)

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_unverified_user_rejected_by_jwt_and_login_code_flow(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.unverified_token}')
        me_res = self.client.get('/api/auth/me/')
        self.assertEqual(me_res.status_code, 401)

        # Unverified account must not receive or redeem a one-time login code
        self.client.credentials()
        req_res = self.client.post('/api/auth/login-code/request/', {'email': self.unverified_student.email}, format='json')
        self.assertEqual(req_res.status_code, 200)
        self.unverified_student.refresh_from_db()
        self.assertEqual(self.unverified_student.login_code_hash, '')

        # Even if a login code exists on an unverified user, login_with_code rejects with 'unverified'
        User.objects.filter(pk=self.unverified_student.pk).update(
            login_code_hash=hash_token('654321'),
            login_code_expires=timezone.now() + timedelta(minutes=10),
        )
        ver_res = self.client.post(
            '/api/auth/login-code/verify/',
            {'email': self.unverified_student.email, 'code': '654321'},
            format='json',
        )
        self.assertEqual(ver_res.status_code, 400)
        self.unverified_student.refresh_from_db()
        self.assertFalse(self.unverified_student.verified)

    def test_otp_lockout_burns_code_hash(self):
        # Reset password OTP must be cleared on lockout so clearing rate limit cannot still use the old code
        User.objects.filter(pk=self.verified_student.pk).update(
            reset_code_hash=hash_token('246810'),
            reset_code_expires=timezone.now() + timedelta(minutes=15),
        )
        for _ in range(5):
            r = self.client.post('/api/auth/reset-password/', {
                'email': self.verified_student.email,
                'code': '000000',
                'password': 'NewPassword123',
            }, format='json')
            self.assertEqual(r.status_code, 400)

        locked = self.client.post('/api/auth/reset-password/', {
            'email': self.verified_student.email,
            'code': '246810',
            'password': 'NewPassword123',
        }, format='json')
        self.assertEqual(locked.status_code, 429)

        # Even after the rate-limit window resets, the burned OTP must remain invalid
        _RATE_LIMIT_CACHE.clear()
        after_window = self.client.post('/api/auth/reset-password/', {
            'email': self.verified_student.email,
            'code': '246810',
            'password': 'NewPassword123',
        }, format='json')
        self.assertEqual(after_window.status_code, 400)

    def test_duplicate_verified_reference_id_rejected_on_register(self):
        res = self.client.post('/api/auth/register/', {
            'fullName': 'Clone Student',
            'email': 'clone.ref@st.knust.edu.gh',
            'referenceId': self.verified_student.reference_id,
            'phone': '0248200099',
            'accountType': 'customer',
            'password': 'Password123',
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertFalse(User.objects.filter(email='clone.ref@st.knust.edu.gh').exists())


class MoneyPrecisionAndConstraintsTest(TestCase):
    """
    FINDING-06 / Section 4 Mandatory Fix:
      - Money fields must be DecimalField(max_digits=10, decimal_places=2).
      - Order.payment_reference must have unique=True while allowing multiple NULLs.
      - DB CheckConstraints reject negative stock/totals, price < 0.50, and ratings outside 1..5.
      - Decimal arithmetic prevents IEEE-754 float drift while keeping JSON responses numeric.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='dec.student@st.knust.edu.gh',
            password='Password123',
            full_name='Decimal Student',
            reference_id='20883001',
            phone='0248300001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.student_token = generate_jwt_token(cls.student)
        cls.vendor_user = User.objects.create_user(
            email='dec.vendor@st.knust.edu.gh',
            password='Password123',
            full_name='Decimal Chef',
            reference_id='20883002',
            phone='0248300002',
            hall='Unity Hall (Conti)',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Exact Pesewa Pot',
        )
        cls.vendor = Vendor.objects.create(
            id='v_dec1',
            user=cls.vendor_user,
            name='Exact Pesewa Pot',
            hall='Unity Hall (Conti)',
            open=True,
            active=True,
        )
        cls.meal = Meal.objects.create(
            id='m_dec1',
            vendor=cls.vendor,
            name='Precision Jollof',
            price=19.99,
            cat='Rice & stews',
            left=20,
            on=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_money_fields_are_decimal_and_constraints_enforced(self):
        for model_cls, field_name in [
            (Meal, 'price'),
            (Order, 'subtotal'),
            (Order, 'fee'),
            (Order, 'total'),
            (Order, 'settlement_net'),
            (PayoutBatch, 'amount'),
        ]:
            field = model_cls._meta.get_field(field_name)
            self.assertIsInstance(field, models.DecimalField, f"{model_cls.__name__}.{field_name} must be DecimalField")
            self.assertEqual(field.max_digits, 10)
            self.assertEqual(field.decimal_places, 2)

        # Unique payment_reference (allowing multiple NULLs)
        Order.objects.create(
            id='STW-NULL1',
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            pickup_day='2026-11-20',
            payment_reference=None,
        )
        Order.objects.create(
            id='STW-NULL2',
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            pickup_day='2026-11-20',
            payment_reference=None,
        )
        Order.objects.create(
            id='STW-REF1',
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            pickup_day='2026-11-20',
            payment_reference='PSK-UNIQ-1',
        )
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Order.objects.create(
                    id='STW-REF2',
                    email=self.student.email,
                    phone=self.student.phone,
                    area='Campus',
                    vendor=self.vendor,
                    vendor_name=self.vendor.name,
                    pickup_day='2026-11-20',
                    payment_reference='PSK-UNIQ-1',
                )

        # CheckConstraints: negative stock, price < 0.50, negative total, invalid rating
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Meal.objects.create(id='m_neg_stock', vendor=self.vendor, name='Bad Stock', price=Decimal('10.00'), left=-1)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Meal.objects.create(id='m_low_price', vendor=self.vendor, name='Too Cheap', price=Decimal('0.25'), left=1)

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Order.objects.create(
                    id='STW-NEG',
                    email=self.student.email,
                    phone=self.student.phone,
                    area='Campus',
                    vendor=self.vendor,
                    vendor_name=self.vendor.name,
                    pickup_day='2026-11-20',
                    total=Decimal('-5.00'),
                )

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                Review.objects.create(order_id='STW-BADREV', vendor=self.vendor, customer=self.student, rating=6)

    def test_order_totals_use_exact_decimal_rounding_and_numeric_json(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 3}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-11-20',
        }, format='json')
        self.assertEqual(res.status_code, 201)
        order = Order.objects.get(pk=res.data['id'])
        self.assertEqual(order.subtotal, Decimal('59.97'))
        self.assertEqual(order.fee, Decimal('3.00'))
        self.assertEqual(order.total, Decimal('62.97'))
        self.assertIsInstance(res.data['subtotal'], float)
        self.assertAlmostEqual(res.data['subtotal'], 59.97, places=2)
        self.assertAlmostEqual(res.data['fee'], 3.00, places=2)
        self.assertAlmostEqual(res.data['total'], 62.97, places=2)

    def test_migration_0003_normalizes_float_drift_and_blank_payment_refs(self):
        import importlib
        from django.apps import apps

        mig = importlib.import_module('api.migrations.0003_decimal_money_and_constraints')
        self.assertEqual(mig._quantize(59.970000000000006), Decimal('59.97'))
        self.assertEqual(mig._quantize(2.9999999999999996), Decimal('3.00'))
        self.assertEqual(mig._quantize(0.10, Decimal('0.50')), Decimal('0.50'))

        # Simulate legacy empty-string payment_reference before normalization
        legacy = Order.objects.create(
            id='STW-LEG1',
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            pickup_day='2026-11-20',
            subtotal=59.97,
            fee=3.00,
            total=62.97,
            payment_reference='',
        )
        mig.normalize_existing_rows(apps, None)
        legacy.refresh_from_db()
        self.assertIsNone(legacy.payment_reference)
        self.assertEqual(legacy.subtotal, Decimal('59.97'))


class RateLimitPaginationAndSettingsSecurityTests(TestCase):
    """
    FINDING-07 & FINDING-08:
      - Unbounded list endpoints support ?limit=&offset= and enforce a safe max row bound.
      - Write/payment/meetup/review/vendor/push endpoints enforce check_rate_limit (429).
      - settings.py enforces cookie HttpOnly/SameSite, COOP, and DATA_UPLOAD_MAX_MEMORY_SIZE.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='rl.student@st.knust.edu.gh',
            password='Password123',
            full_name='RateLimit Student',
            reference_id='20884001',
            phone='0248400001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.student_token = generate_jwt_token(cls.student)
        cls.vendor_user = User.objects.create_user(
            email='rl.vendor@st.knust.edu.gh',
            password='Password123',
            full_name='RateLimit Chef',
            reference_id='20884002',
            phone='0248400002',
            hall='Unity Hall (Conti)',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Bounded Kitchen',
        )
        cls.vendor = Vendor.objects.create(
            id='v_rl1',
            user=cls.vendor_user,
            name='Bounded Kitchen',
            hall='Unity Hall (Conti)',
            open=True,
            active=True,
        )
        cls.m1 = Meal.objects.create(id='m_rl1', vendor=cls.vendor, name='Dish One', price=Decimal('20.00'), left=50, on=True)
        cls.m2 = Meal.objects.create(id='m_rl2', vendor=cls.vendor, name='Dish Two', price=Decimal('25.00'), left=50, on=True)
        cls.o1 = Order.objects.create(
            id='STW-RL1', customer=cls.student, email=cls.student.email, phone=cls.student.phone,
            area='Campus', vendor=cls.vendor, vendor_name=cls.vendor.name, pickup_day='2026-11-20',
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'), payment_status='pending',
        )
        cls.o2 = Order.objects.create(
            id='STW-RL2', customer=cls.student, email=cls.student.email, phone=cls.student.phone,
            area='Campus', vendor=cls.vendor, vendor_name=cls.vendor.name, pickup_day='2026-11-20',
            subtotal=Decimal('25.00'), fee=Decimal('1.25'), total=Decimal('26.25'), payment_status='pending',
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_list_endpoints_honor_limit_and_offset(self):
        res_meals = self.client.get('/api/meals/?limit=1')
        self.assertEqual(res_meals.status_code, 200)
        self.assertIsInstance(res_meals.data, list)
        self.assertEqual(len(res_meals.data), 1)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res_orders = self.client.get('/api/orders/?limit=1')
        self.assertEqual(res_orders.status_code, 200)
        self.assertEqual(len(res_orders.data), 1)

    def test_payment_init_and_order_create_rate_limited(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        statuses_pay = []
        for _ in range(16):
            r = self.client.post('/api/payments/initialize/', {'orderId': self.o1.id}, format='json')
            statuses_pay.append(r.status_code)
        self.assertEqual(statuses_pay[-1], 429)

        _RATE_LIMIT_CACHE.clear()
        statuses_ord = []
        for _ in range(21):
            r = self.client.post('/api/orders/', {
                'lines': [{'mealId': self.m1.id, 'qty': 1}],
                'area': 'Campus',
                'pickupDay': '2026-11-20',
            }, format='json')
            statuses_ord.append(r.status_code)
        self.assertEqual(statuses_ord[-1], 429)

    def test_django_security_headers_cookies_and_upload_limit(self):
        self.assertLessEqual(settings.DATA_UPLOAD_MAX_MEMORY_SIZE, 2621440)
        self.assertTrue(settings.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(settings.CSRF_COOKIE_HTTPONLY)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Lax')
        self.assertEqual(settings.CSRF_COOKIE_SAMESITE, 'Lax')
        self.assertEqual(settings.SECURE_CROSS_ORIGIN_OPENER_POLICY, 'same-origin')


class Migration0003MessyDataTests(TestCase):
    """
    FIN-02: Migration 0003 must safely clean messy float values, non-finite inputs,
    out-of-range decimals, and duplicate/long payment references on PostgreSQL.
    """

    @staticmethod
    def _mig():
        import importlib
        return importlib.import_module('api.migrations.0003_decimal_money_and_constraints')

    def test_quantize_handles_half_up_floats_nan_inf_and_overflow(self):
        mig = self._mig()
        self.assertEqual(mig._quantize(10.005, Decimal('0.50')), Decimal('10.01'))
        self.assertEqual(mig._quantize(0.1 + 0.2, Decimal('0.00')), Decimal('0.30'))
        self.assertEqual(mig._quantize(-50.0, Decimal('0.00')), Decimal('0.00'))
        self.assertEqual(mig._quantize(float('nan'), Decimal('0.50')), Decimal('0.50'))
        self.assertEqual(mig._quantize(float('inf'), Decimal('0.00')), Decimal('0.00'))
        self.assertEqual(mig._quantize(1e15, Decimal('0.00')), Decimal('99999999.99'))
        self.assertEqual(mig._quantize('not-a-number', Decimal('0.00')), Decimal('0.00'))

    def test_normalize_deduplicates_shared_pk_prefix_and_long_payment_references(self):
        mig = self._mig()
        from types import SimpleNamespace
        long_ref = 'R' * 125
        rows = [
            SimpleNamespace(pk='ordpref1-aaa', id='ordpref1-aaa', payment_reference='SAMEREF',
                            subtotal=10.0, fee=1.0, total=11.0, settlement_net=10.0),
            SimpleNamespace(pk='ordpref1-bbb', id='ordpref1-bbb', payment_reference='SAMEREF',
                            subtotal=10.0, fee=1.0, total=11.0, settlement_net=10.0),
            SimpleNamespace(pk='ordpref1-ccc', id='ordpref1-ccc', payment_reference='SAMEREF',
                            subtotal=10.0, fee=1.0, total=11.0, settlement_net=10.0),
            SimpleNamespace(pk='ordlong-1111', id='ordlong-1111', payment_reference=long_ref,
                            subtotal=10.0, fee=1.0, total=11.0, settlement_net=10.0),
            SimpleNamespace(pk='ordlong-2222', id='ordlong-2222', payment_reference=long_ref,
                            subtotal=10.0, fee=1.0, total=11.0, settlement_net=10.0),
            SimpleNamespace(pk='ordblank-1', id='ordblank-1', payment_reference='   ',
                            subtotal=0.0, fee=0.0, total=0.0, settlement_net=0.0),
        ]

        class _QS(list):
            def order_by(self, *args):
                return self

        class _Mgr:
            def __init__(self, items):
                self._items = items
                self.updates = {}

            def all(self):
                return _QS(self._items)

            def filter(self, pk=None, **kwargs):
                mgr = self

                class _Up:
                    def update(self, **u):
                        mgr.updates[pk] = u
                return _Up()

        class _Apps:
            def __init__(self):
                self.order_mgr = _Mgr(rows)
                self.empty = _Mgr([])

            def get_model(self, app, name):
                m = self.order_mgr if name == 'Order' else self.empty
                return SimpleNamespace(objects=m)

        fake_apps = _Apps()
        mig.normalize_existing_rows(fake_apps, None)
        final_refs = {}
        for r in rows:
            final_refs[r.pk] = fake_apps.order_mgr.updates.get(r.pk, {}).get('payment_reference', r.payment_reference)

        self.assertIsNone(final_refs['ordblank-1'])
        non_null = [v for v in final_refs.values() if v is not None]
        self.assertEqual(len(non_null), len(set(non_null)))
        for ref in non_null:
            self.assertLessEqual(len(ref), 128)


class PostgresLockingAndConcurrencyTests(TransactionTestCase):
    """
    FIN-03: Verifies PostgreSQL-safe select_for_update() (no nullable outer joins),
    deterministic ascending Meal lock ordering, and safe multi-thread races.
    """

    def setUp(self):
        self.student = User.objects.create_user(
            email='pgcust1@st.knust.edu.gh', password='Password123',
            verified=True, phone='+233240000101', hall='Unity',
        )
        self.student2 = User.objects.create_user(
            email='pgcust2@st.knust.edu.gh', password='Password123',
            verified=True, phone='+233240000102', hall='Independence',
        )
        self.vendor_user = User.objects.create_user(
            email='pgvend@st.knust.edu.gh', password='Password123',
            verified=True, is_vendor=True, role='vendor', account_type='vendor',
            phone='+233240000103', hall='Repub',
        )
        self.admin_user = User.objects.create_user(
            email='pgadmin@st.knust.edu.gh', password='Password123',
            verified=True, is_admin=True, is_staff=True, role='admin', account_type='admin',
            phone='+233240000104', hall='Admin',
        )
        self.vendor = Vendor.objects.create(
            id='V-PG-1', user=self.vendor_user, name='PG Kitchen',
            hall='Repub', active=True, open=True,
        )
        self.meal_a = Meal.objects.create(
            id='meal-pg-a', vendor=self.vendor, name='Banku',
            price=Decimal('15.00'), cat='local', left=10, on=True,
        )
        self.meal_z = Meal.objects.create(
            id='meal-pg-z', vendor=self.vendor, name='Jollof',
            price=Decimal('20.00'), cat='rice', left=10, on=True,
        )

    def _auth_client(self, user):
        c = APIClient()
        c.force_authenticate(user=user)
        return c

    def test_select_for_update_endpoints_succeed_without_nullable_outer_join_and_lock_meals_sorted(self):
        # 1. Create order with meal-z before meal-a and verify Meal lock query uses ascending ORDER BY id
        c_cust = self._auth_client(self.student)
        with CaptureQueriesContext(connection) as ctx:
            r_ord = c_cust.post('/api/orders/', {
                'lines': [
                    {'mealId': self.meal_z.id, 'qty': 1},
                    {'mealId': self.meal_a.id, 'qty': 1},
                ],
                'area': 'Unity',
                'pickupDay': '2026-11-25',
            }, format='json')
        self.assertEqual(r_ord.status_code, 201, r_ord.data)
        meal_lock_sql = [
            q['sql'] for q in ctx.captured_queries
            if 'api_meal' in q['sql'] and 'SELECT' in q['sql'] and 'meal-pg-a' in q['sql'] and 'meal-pg-z' in q['sql']
        ]
        self.assertTrue(meal_lock_sql and any('ORDER BY' in s and 'id' in s for s in meal_lock_sql), meal_lock_sql)

        # Verify _restore_order_stock locks Meal rows in ascending id order too
        o_cancel = Order.objects.get(id=r_ord.data['id'])
        Order.objects.filter(id=o_cancel.id).update(payment_status='paid', prep_stage='accepted')
        with CaptureQueriesContext(connection) as ctx_cancel:
            r_cancel = c_cust.post(f'/api/orders/{o_cancel.id}/cancel/', {}, format='json')
        self.assertEqual(r_cancel.status_code, 200, r_cancel.data)
        restore_sql = [
            q['sql'] for q in ctx_cancel.captured_queries
            if 'api_meal' in q['sql'] and 'SELECT' in q['sql'] and 'ORDER BY' in q['sql']
        ]
        self.assertTrue(restore_sql, ctx_cancel.captured_queries)

        # 2. complete_by_code_view + create_review_view + mark_collected_view + payout_batches_view on PostgreSQL
        o_code = Order.objects.create(
            id='STW-PG-CODE', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='paid', prep_stage='ready', handoff_code='654321',
            lines=[{'mealId': self.meal_a.id, 'qty': 1}],
        )
        c_vend = self._auth_client(self.vendor_user)
        r_complete = c_vend.post(f'/api/orders/{o_code.id}/complete/', {'code': '654321'}, format='json')
        self.assertEqual(r_complete.status_code, 200, r_complete.data)

        r_review = c_cust.post('/api/reviews/', {'orderId': o_code.id, 'rating': 5, 'text': 'Great!'}, format='json')
        self.assertEqual(r_review.status_code, 201, r_review.data)

        o_coll = Order.objects.create(
            id='STW-PG-COLL', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('15.00'), fee=Decimal('0.75'), total=Decimal('15.75'),
            payment_status='paid', prep_stage='ready', handoff_code='112233',
            lines=[{'mealId': self.meal_a.id, 'qty': 1}],
        )
        r_coll = c_cust.post(f'/api/orders/{o_coll.id}/collected/', {}, format='json')
        self.assertEqual(r_coll.status_code, 200, r_coll.data)

        c_admin = self._auth_client(self.admin_user)
        with CaptureQueriesContext(connection) as ctx_batch:
            r_batch = c_admin.post('/api/payouts/batches/', {}, format='json')
        self.assertEqual(r_batch.status_code, 201, r_batch.data)
        self.assertEqual(r_batch.data['orderCount'], 2)
        for q in ctx_batch.captured_queries:
            if 'FOR UPDATE' in q['sql']:
                self.assertNotIn('LEFT OUTER JOIN', q['sql'])

    def test_postgresql_threaded_stock_cancel_complete_and_payout_races(self):
        if connection.vendor != 'postgresql':
            self.skipTest('Multi-thread row-lock race runs against PostgreSQL')

        import threading
        Meal.objects.filter(id=self.meal_a.id).update(left=1)

        def _race(targets):
            barrier = threading.Barrier(len(targets))
            results = []
            lock = threading.Lock()

            def _worker(fn):
                connections.close_all()
                try:
                    barrier.wait(timeout=5)
                    res = fn()
                    with lock:
                        results.append(res)
                finally:
                    connections.close_all()

            threads = [threading.Thread(target=_worker, args=(fn,)) for fn in targets]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
            return results

        # Race 1: Two students ordering the last remaining portion (left=1)
        def _place_for(u):
            c = APIClient()
            c.force_authenticate(user=u)
            return c.post('/api/orders/', {
                'lines': [{'mealId': self.meal_a.id, 'qty': 1}],
                'area': 'Unity',
                'pickupDay': '2026-11-25',
            }, format='json').status_code

        statuses = _race([lambda: _place_for(self.student), lambda: _place_for(self.student2)])
        self.assertEqual(sorted(statuses), [201, 400], statuses)
        self.meal_a.refresh_from_db()
        self.assertEqual(self.meal_a.left, 0)

        # Race 2: Concurrent cancel vs complete_by_code on the same order
        race_order = Order.objects.create(
            id='STW-PG-RACE2', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('15.00'), fee=Decimal('0.75'), total=Decimal('15.75'),
            payment_status='paid', prep_stage='ready', handoff_code='789012',
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )

        def _cancel_race():
            c = APIClient()
            c.force_authenticate(user=self.vendor_user)
            return c.post(f'/api/orders/{race_order.id}/cancel/', {}, format='json').status_code

        def _complete_race():
            c = APIClient()
            c.force_authenticate(user=self.vendor_user)
            return c.post(f'/api/orders/{race_order.id}/complete/', {'code': '789012'}, format='json').status_code

        race2_statuses = _race([_cancel_race, _complete_race])
        self.assertEqual(sorted(race2_statuses), [200, 400], race2_statuses)
        race_order.refresh_from_db()
        self.assertNotEqual(bool(race_order.cancelled_at), bool(race_order.collected_at))

        # Race 3: Two admins creating payout batches concurrently
        Order.objects.create(
            id='STW-PG-RACE3', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='released', settlement_status='released',
            prep_stage='collected', collected_at=timezone.now(),
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )

        def _batch_race():
            c = APIClient()
            c.force_authenticate(user=self.admin_user)
            return c.post('/api/payouts/batches/', {}, format='json').status_code

        race3_statuses = _race([_batch_race, _batch_race])
        self.assertEqual(sorted(race3_statuses), [201, 400], race3_statuses)


class PaginationAndAggregateTests(TestCase):
    """
    FIN-05: List endpoints expose pagination headers/envelope (including admin audit)
    and payout/dashboard aggregates compute totals over the full queryset, not the
    truncated page slice.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='pag.admin@st.knust.edu.gh', password='AdminPassword123',
            full_name='Pag Admin',
        )
        cls.vendor_user = User.objects.create_user(
            email='pag.vendor@st.knust.edu.gh', password='Password123',
            verified=True, is_vendor=True, role='vendor', account_type='vendor',
        )
        cls.student = User.objects.create_user(
            email='pag.cust@st.knust.edu.gh', password='Password123',
            verified=True,
        )
        cls.vendor = Vendor.objects.create(id='v-pag-1', user=cls.vendor_user, name='Pag Kitchen', hall='Unity', active=True, open=True)
        cls.meals = [
            Meal.objects.create(id=f'm-pag-{i}', vendor=cls.vendor, name=f'Meal {i}', price=Decimal('10.00'), left=5, on=True)
            for i in range(4)
        ]
        cls.orders = []
        for i in range(3):
            cls.orders.append(Order.objects.create(
                id=f'STW-PAG-{i}', customer=cls.student, email=cls.student.email,
                vendor=cls.vendor, vendor_name=cls.vendor.name,
                subtotal=Decimal('15.00'), fee=Decimal('0.75'), total=Decimal('15.75'),
                payment_status='paid', prep_stage='ready' if i < 2 else 'accepted',
                handoff_code=f'12345{i}', lines=[{'mealId': cls.meals[0].id, 'qty': 1}],
            ))
        from api.models import AuditEntry
        for i in range(5):
            AuditEntry.objects.create(id=f'AUD-PAG-{i}', actor=cls.admin.email, action='test_evt', entity_type='order', entity_id=f'STW-PAG-{i%3}')
        SupportCase.objects.create(code='CASE-PAG-1', user=cls.student, type='safety', priority='high')

    def setUp(self):
        self.client = APIClient()

    def test_list_endpoints_return_pagination_headers_and_optional_envelope_and_audit_paginates(self):
        res_meals = self.client.get('/api/meals/?limit=2&offset=1')
        self.assertEqual(res_meals.status_code, 200)
        self.assertEqual(len(res_meals.data), 2)
        self.assertEqual(res_meals['X-Total-Count'], '4')
        self.assertEqual(res_meals['X-Result-Limit'], '2')
        self.assertEqual(res_meals['X-Result-Offset'], '1')
        self.assertEqual(res_meals['X-Truncated'], 'true')

        res_env = self.client.get('/api/meals/?limit=2&offset=2&envelope=true')
        self.assertEqual(res_env.status_code, 200)
        self.assertIsInstance(res_env.data, dict)
        self.assertEqual(res_env.data['total'], 4)
        self.assertEqual(res_env.data['limit'], 2)
        self.assertEqual(res_env.data['offset'], 2)
        self.assertFalse(res_env.data['truncated'])
        self.assertEqual(len(res_env.data['results']), 2)

        self.client.force_authenticate(user=self.admin)
        res_audit = self.client.get('/api/admin/audit/?limit=2&offset=0')
        self.assertEqual(res_audit.status_code, 200)
        self.assertEqual(len(res_audit.data), 2)
        self.assertEqual(res_audit['X-Truncated'], 'true')
        self.assertGreaterEqual(int(res_audit['X-Total-Count']), 5)

    def test_payout_ledger_returns_full_set_aggregates_for_vendor_and_admin(self):
        self.client.force_authenticate(user=self.vendor_user)
        v_ledger = self.client.get('/api/payouts/?limit=1')
        self.assertEqual(v_ledger.status_code, 200)
        self.assertEqual(v_ledger.data['held'], 45.0)
        self.assertEqual(v_ledger.data['heldCount'], 3)
        self.assertEqual(v_ledger.data['weekTotal'], 45.0)
        self.assertEqual(v_ledger.data['readyCount'], 2)
        self.assertEqual(v_ledger.data['newCount'], 1)
        self.assertEqual(v_ledger.data['inProgressCount'], 3)
        self.assertEqual(len(v_ledger.data['salesByDay']), 7)
        self.assertAlmostEqual(sum(d['v'] for d in v_ledger.data['salesByDay']), 45.0, places=2)

        self.client.force_authenticate(user=self.admin)
        a_ledger = self.client.get('/api/payouts/?limit=1')
        self.assertEqual(a_ledger.status_code, 200)
        self.assertGreaterEqual(a_ledger.data['ordersToday'], 3)
        self.assertGreaterEqual(a_ledger.data['activeVendorsCount'], 1)
        self.assertGreaterEqual(a_ledger.data['openDisputesCount'], 1)
        self.assertGreaterEqual(a_ledger.data['highPriorityDisputesCount'], 1)


class PersistentRateLimitAndHandoffTests(TestCase):
    """
    FIN-06: Security-critical rate limits persist in DB across worker/cache resets,
    ignore X-Forwarded-For header spoofing, rotate handoff codes on 429 lockout,
    clear handoff codes upon collection (single-use), and expire codes after 14 days.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='rl.cust@st.knust.edu.gh', password='Password123',
            verified=True, phone='+233240000201', hall='Unity',
        )
        cls.vendor_user = User.objects.create_user(
            email='rl.vendor@st.knust.edu.gh', password='Password123',
            verified=True, is_vendor=True, role='vendor', account_type='vendor',
            phone='+233240000202', hall='Repub',
        )
        cls.vendor = Vendor.objects.create(
            id='v-rl-1', user=cls.vendor_user, name='RL Kitchen', hall='Repub', active=True, open=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_rate_limit_persists_in_database_across_worker_memory_and_cache_flush(self):
        from django.core.cache import cache
        from api.security import check_rate_limit

        for _ in range(3):
            self.assertTrue(check_rate_limit('persist_test_key', limit=3, window_seconds=600))

        # Simulate worker restart / in-memory dict + Django cache eviction
        dict.clear(_RATE_LIMIT_CACHE)
        cache.clear()
        self.assertFalse(check_rate_limit('persist_test_key', limit=3, window_seconds=600))

    def test_xff_and_header_spoofing_cannot_bypass_otp_login_reset_pay_or_handoff_lockout(self):
        # Set active codes for verify-email, login-code, reset-password
        now = timezone.now()
        self.student.verification_code_hash = hash_token('111111')
        self.student.verification_code_expires = now + timedelta(minutes=10)
        self.student.login_code_hash = hash_token('222222')
        self.student.login_code_expires = now + timedelta(minutes=10)
        self.student.reset_code_hash = hash_token('333333')
        self.student.reset_code_expires = now + timedelta(minutes=10)
        self.student.save()

        def spoof(i):
            return {'HTTP_X_FORWARDED_FOR': f'198.51.100.{i}', 'HTTP_X_REAL_IP': f'203.0.113.{i}'}

        # 1. Verify email OTP lockout despite XFF spoofing
        for i in range(6):
            r = self.client.post('/api/auth/verify-email/', {'email': self.student.email, 'code': '000000'}, format='json', **spoof(i))
        self.assertEqual(r.status_code, 429)

        # 2. Login code verify lockout despite XFF spoofing
        for i in range(6):
            r = self.client.post('/api/auth/login-code/verify/', {'email': self.student.email, 'code': '000000'}, format='json', **spoof(i + 20))
        self.assertEqual(r.status_code, 429)

        # 3. Password reset verify lockout despite XFF spoofing
        for i in range(6):
            r = self.client.post('/api/auth/reset-password/', {'email': self.student.email, 'code': '000000', 'newPassword': 'NewPassword123'}, format='json', **spoof(i + 40))
        self.assertEqual(r.status_code, 429)

        # 4. Payment initiation lockout despite XFF spoofing
        order = Order.objects.create(
            id='STW-RL-PAY', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', handoff_code='445566',
        )
        self.client.force_authenticate(user=self.student)
        for i in range(16):
            r = self.client.post('/api/payments/initialize/', {'orderId': order.id}, format='json', **spoof(i + 60))
        self.assertEqual(r.status_code, 429)

    def test_handoff_code_rotates_on_lockout_clears_on_collection_and_expires_after_14_days(self):
        order = Order.objects.create(
            id='STW-RL-HC1', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('25.00'), fee=Decimal('1.25'), total=Decimal('26.25'),
            payment_status='paid', prep_stage='ready', handoff_code='889900',
        )
        self.client.force_authenticate(user=self.vendor_user)

        for i in range(5):
            r = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '000000'}, format='json', HTTP_X_FORWARDED_FOR=f'10.0.0.{i}')
            self.assertEqual(r.status_code, 400)

        r_lock = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '889900'}, format='json', HTTP_X_FORWARDED_FOR='10.0.0.99')
        self.assertEqual(r_lock.status_code, 429)

        order.refresh_from_db()
        self.assertNotEqual(order.handoff_code, '889900')
        self.assertEqual(len(order.handoff_code), 6)

        # Even if rate limit resets after window, old code no longer works; new rotated code succeeds & clears
        _RATE_LIMIT_CACHE.clear()
        r_old = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '889900'}, format='json')
        self.assertEqual(r_old.status_code, 400)

        r_new = self.client.post(f'/api/orders/{order.id}/complete/', {'code': order.handoff_code}, format='json')
        self.assertEqual(r_new.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.handoff_code, '')

        # Order older than 14 days must reject handoff completion even with valid code
        expired_order = Order.objects.create(
            id='STW-RL-EXP', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('15.00'), fee=Decimal('0.75'), total=Decimal('15.75'),
            payment_status='paid', prep_stage='ready', handoff_code='135790',
        )
        Order.objects.filter(id=expired_order.id).update(created_at=timezone.now() - timedelta(days=15))
        r_exp = self.client.post(f'/api/orders/{expired_order.id}/complete/', {'code': '135790'}, format='json')
        self.assertEqual(r_exp.status_code, 400)


class AtomicStateAndUploadSecurityTests(TestCase):
    """
    FIN-07 & FIN-08: Refusing paid state revival on cancelled orders, blocking
    meetup/chat/nudge on unpaid orders under row locks, idempotent stock
    restoration, blocking support refunds for orders already in PayoutBatch,
    and strict image/SVG/protocol-relative/oversized-upload sanitization.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='atom.admin@st.knust.edu.gh', password='AdminPassword123',
            full_name='Atom Admin',
        )
        cls.student = User.objects.create_user(
            email='atom.cust@st.knust.edu.gh', password='Password123',
            verified=True, phone='+233240000301', hall='Unity',
        )
        cls.vendor_user = User.objects.create_user(
            email='atom.vendor@st.knust.edu.gh', password='Password123',
            verified=True, is_vendor=True, role='vendor', account_type='vendor',
            phone='+233240000302', hall='Repub',
        )
        cls.vendor = Vendor.objects.create(
            id='v-atom-1', user=cls.vendor_user, name='Atom Kitchen',
            hall='Repub', active=True, open=True,
        )
        cls.meal = Meal.objects.create(
            id='m-atom-1', vendor=cls.vendor, name='Atom Waakye',
            price=Decimal('20.00'), left=5, on=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_mark_order_paid_refuses_cancelled_or_refunded_order(self):
        from api.views import _mark_order_paid
        now = timezone.now()
        o_can = Order.objects.create(
            id='STW-ATOM-CAN', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='cancelled', cancelled_at=now,
        )
        _mark_order_paid(o_can, 'paystack_webhook', 'PSK-CAN-1')
        o_can.refresh_from_db()
        self.assertEqual(o_can.payment_status, 'cancelled')
        self.assertIsNone(o_can.paid_at)

    def test_meetup_chat_and_nudge_block_unpaid_orders(self):
        unpaid = Order.objects.create(
            id='STW-ATOM-UNPAID', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', prep_stage='accepted',
            meetup={'place': 'Gate', 'proposedBy': 'vendor', 'confirmedBy': ['vendor'], 'agreed': False},
        )
        self.client.force_authenticate(user=self.student)
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/meetup/propose/', {'place': 'Hall'}, format='json').status_code, 400)
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/meetup/confirm/', {}, format='json').status_code, 400)
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/meetup/decline/', {}, format='json').status_code, 400)
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/messages/', {'text': 'Hi'}, format='json').status_code, 400)

        self.client.force_authenticate(user=self.vendor_user)
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/collection-nudge/', {}, format='json').status_code, 400)

    def test_restore_order_stock_is_idempotent(self):
        from api.views import _restore_order_stock
        order = Order.objects.create(
            id='STW-ATOM-RST', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'qty': 2}],
            subtotal=Decimal('40.00'), fee=Decimal('2.00'), total=Decimal('42.00'),
            payment_status='cancelled', cancelled_at=timezone.now(),
        )
        before = Meal.objects.get(id=self.meal.id).left
        _restore_order_stock(order)
        _restore_order_stock(order)
        after = Meal.objects.get(id=self.meal.id).left
        self.assertEqual(after, before + 2)

    def test_support_case_resolve_refund_blocks_order_in_payout_batch(self):
        batch = PayoutBatch.objects.create(id='PAY-ATOM-1', amount=Decimal('20.00'), order_count=1)
        order = Order.objects.create(
            id='STW-ATOM-BATCHED', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='released', settlement_status='released',
            prep_stage='collected', collected_at=timezone.now(), payout_batch_id=batch.id,
        )
        case = SupportCase.objects.create(code='CASE-ATOM-1', user=self.student, type='quality', order=order.id)
        self.client.force_authenticate(user=self.admin)
        res = self.client.post(f'/api/support/cases/{case.code}/resolve/', {'action': 'refund'}, format='json')
        self.assertEqual(res.status_code, 409)
        order.refresh_from_db()
        self.assertIsNone(order.cancelled_at)
        self.assertTrue(SupportCase.objects.filter(code=case.code).exists())

    def test_media_url_sanitization_blocks_svg_protocol_relative_and_oversized_while_accepting_jpeg(self):
        from rest_framework.exceptions import ValidationError as DRFValidationError
        from api.views import _sanitize_media_url

        for bad in (
            'data:image/svg+xml;base64,PHN2Zz4=',
            'data:image/svg+xml,<svg onload=alert(1)>',
            '//evil.example/tracker.png',
            'data:image/jpeg;base64,' + ('QUJD' * 160000),  # > 600,000 chars
        ):
            with self.assertRaises(DRFValidationError, msg=f'Should reject {bad[:40]}'):
                _sanitize_media_url(bad)

        valid_jpeg = 'data:image/jpeg;base64,' + ('QUJD' * 50000)  # ~200 KB compressed JPEG
        self.assertEqual(_sanitize_media_url(valid_jpeg), valid_jpeg)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_user)}')
        r_ok = self.client.post('/api/meals/', {
            'name': 'Valid Photo Meal', 'price': 25, 'stock': 4, 'cat': 'Soups', 'image': valid_jpeg,
        }, format='json')
        self.assertEqual(r_ok.status_code, 201, r_ok.data)


class PaystackHardeningTests(TestCase):
    """
    FIN-10: PAYSTACK_ALLOW_MOCK must be impossible when DEBUG=False, webhook payloads must validate
    event data amount/currency/status before touching escrow, and init_payment must lock/reuse ref.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='fin10.student@st.knust.edu.gh', password='Password123',
            full_name='Fin10 Student', reference_id='20891001', phone='0249100001',
            hall='Unity Hall', verified=True, role='customer', account_type='customer',
        )
        cls.vendor_user = User.objects.create_user(
            email='fin10.vendor@st.knust.edu.gh', password='Password123',
            full_name='Fin10 Vendor', reference_id='20891002', phone='0249100002',
            hall='Unity Hall', verified=True, role='vendor', account_type='vendor', is_vendor=True,
        )
        cls.vendor = Vendor.objects.create(
            id='v_fin10', user=cls.vendor_user, name='Fin10 Kitchen',
            hall='Unity Hall', open=True, active=True,
        )

    def setUp(self):
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.order = Order.objects.create(
            id='STW-FIN10-1', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', handoff_code='123456',
        )

    @override_settings(DEBUG=False, PAYSTACK_ALLOW_MOCK=True, PAYSTACK_SECRET_KEY='')
    def test_mock_payment_impossible_when_debug_false(self):
        from api.views import _paystack_mock_allowed
        self.assertFalse(_paystack_mock_allowed())
        self.client.force_authenticate(user=self.student)
        r_init = self.client.post('/api/payments/initialize/', {'orderId': self.order.id}, format='json')
        self.assertEqual(r_init.status_code, 503)

        self.order.payment_reference = 'PSK-DBGOFF'
        self.order.save(update_fields=['payment_reference'])
        r_ver = self.client.post('/api/payments/verify/', {'orderId': self.order.id, 'reference': 'PSK-DBGOFF'}, format='json')
        self.assertEqual(r_ver.status_code, 503)
        self.order.refresh_from_db()
        self.assertEqual(self.order.payment_status, 'pending')

    @override_settings(PAYSTACK_SECRET_KEY='sk_test_webhook_sec')
    def test_webhook_rejects_mismatched_amount_currency_or_status_and_unknown_ref(self):
        from api.models import AuditEntry
        self.order.payment_reference = 'PSK-WH-1'
        self.order.save(update_fields=['payment_reference'])

        def post_signed(payload_dict, include_sig=True):
            raw = json.dumps(payload_dict).encode('utf-8')
            sig = hmac.new(b'sk_test_webhook_sec', raw, hashlib.sha512).hexdigest()
            headers = {'HTTP_X_PAYSTACK_SIGNATURE': sig} if include_sig else {}
            return self.client.post('/api/payments/webhook/', data=raw, content_type='application/json', **headers)

        mock_resp = MagicMock(ok=True)
        mock_resp.json.return_value = {
            'status': True,
            'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 2100},
        }

        with patch('api.views.http_requests.get', return_value=mock_resp) as mock_get:
            # Missing signature header -> 400
            r_nosig = post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 2100}}, include_sig=False)
            self.assertEqual(r_nosig.status_code, 400)
            mock_get.assert_not_called()

            # Underpayment in webhook event payload
            post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 100}})
            mock_get.assert_not_called()

            # Wrong currency
            post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'USD', 'amount': 2100}})
            mock_get.assert_not_called()

            # Non-success data.status inside charge.success event
            post_signed({'event': 'charge.success', 'data': {'status': 'failed', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 2100}})
            mock_get.assert_not_called()

            # Unknown / blank reference
            post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-UNKNOWN-999', 'currency': 'GHS', 'amount': 2100}})
            post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': '', 'currency': 'GHS', 'amount': 2100}})
            mock_get.assert_not_called()

            self.order.refresh_from_db()
            self.assertEqual(self.order.payment_status, 'pending')

            # Valid matching webhook succeeds
            r_ok = post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 2100}})
            self.assertEqual(r_ok.status_code, 200)
            self.assertEqual(mock_get.call_count, 1)
            self.order.refresh_from_db()
            self.assertEqual(self.order.payment_status, 'paid')
            first_paid_at = self.order.paid_at

            # Duplicate/replay delivery is idempotent
            r_dup = post_signed({'event': 'charge.success', 'data': {'status': 'success', 'reference': 'PSK-WH-1', 'currency': 'GHS', 'amount': 2100}})
            self.assertEqual(r_dup.status_code, 200)
            self.assertEqual(mock_get.call_count, 1)
            self.order.refresh_from_db()
            self.assertEqual(self.order.paid_at, first_paid_at)
            self.assertEqual(AuditEntry.objects.filter(entity_id=self.order.id, action='payment_verified').count(), 1)

    @override_settings(DEBUG=True, PAYSTACK_ALLOW_MOCK=True, PAYSTACK_SECRET_KEY='')
    def test_init_payment_idempotent_reuses_reference(self):
        self.client.force_authenticate(user=self.student)
        r1 = self.client.post('/api/payments/initialize/', {'orderId': self.order.id}, format='json')
        self.assertEqual(r1.status_code, 200)
        r2 = self.client.post('/api/payments/initialize/', {'orderId': self.order.id}, format='json')
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r1.data['reference'], r2.data['reference'])
        self.order.refresh_from_db()
        self.assertEqual(self.order.payment_reference, r1.data['reference'])


class QuantityAndRatingValidationTests(TestCase):
    """
    FIN-11: Quantities, prep time, and review ratings must strictly validate as whole
    integers inside their domain bounds instead of truncating floats, accepting booleans,
    clamping invalid ratings, or letting split lines exceed max per-dish limits.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='fin11.student@st.knust.edu.gh', password='Password123',
            full_name='Fin11 Student', reference_id='20891101', phone='0249110001',
            hall='Unity Hall', verified=True, role='customer', account_type='customer',
        )
        cls.vendor_user = User.objects.create_user(
            email='fin11.vendor@st.knust.edu.gh', password='Password123',
            full_name='Fin11 Vendor', reference_id='20891102', phone='0249110002',
            hall='Unity Hall', verified=True, role='vendor', account_type='vendor', is_vendor=True,
        )
        cls.vendor = Vendor.objects.create(
            id='v_fin11', user=cls.vendor_user, name='Fin11 Kitchen',
            hall='Unity Hall', open=True, active=True,
        )
        cls.meal = Meal.objects.create(
            id='m_fin11', vendor=cls.vendor, name='Jollof Pack',
            price=Decimal('25.00'), cat='Mains', left=100, on=True,
        )
        cls.collected_order = Order.objects.create(
            id='STW-FIN11-REV', customer=cls.student, email=cls.student.email,
            vendor=cls.vendor, vendor_name=cls.vendor.name,
            subtotal=Decimal('25.00'), fee=Decimal('1.25'), total=Decimal('26.25'),
            payment_status='released', prep_stage='collected',
            collected_at=timezone.now(), handoff_code='',
        )

    def setUp(self):
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.client.force_authenticate(user=self.student)

    def test_order_rejects_fractional_bool_and_duplicate_line_qty_overflow(self):
        for bad_qty in (1.9, '1.5', True):
            r = self.client.post('/api/orders/', {
                'lines': [{'mealId': self.meal.id, 'qty': bad_qty}],
                'area': 'Unity Hall', 'pickupDay': '2026-12-01',
            }, format='json')
            self.assertEqual(r.status_code, 400, f'Expected 400 for qty={bad_qty!r}, got {r.status_code}')

        # Two lines for the same meal totaling 60 (> 50 max per dish)
        r_split = self.client.post('/api/orders/', {
            'lines': [
                {'mealId': self.meal.id, 'qty': 30},
                {'mealId': self.meal.id, 'qty': 30},
            ],
            'area': 'Unity Hall', 'pickupDay': '2026-12-01',
        }, format='json')
        self.assertEqual(r_split.status_code, 400)
        self.meal.refresh_from_db()
        self.assertEqual(self.meal.left, 100)

    def test_review_rejects_out_of_range_float_and_bool_ratings(self):
        for bad_rating in (0, 6, 4.5, '3.5', True):
            r = self.client.post('/api/reviews/', {
                'orderId': self.collected_order.id,
                'rating': bad_rating,
                'text': 'Test review',
            }, format='json')
            self.assertEqual(r.status_code, 400, f'Expected 400 for rating={bad_rating!r}, got {r.status_code}')
        self.assertFalse(Review.objects.filter(order_id=self.collected_order.id).exists())

    def test_me_patch_rejects_bool_and_float_prep_time(self):
        for bad_prep in (True, 15.5, '15.5'):
            r = self.client.patch('/api/auth/me/', {'prep': bad_prep}, format='json')
            self.assertEqual(r.status_code, 400, f'Expected 400 for prep={bad_prep!r}, got {r.status_code}')
