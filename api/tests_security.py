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

from api.models import User, Vendor, Meal, Order, PayoutBatch, PushSubscription, Review, SupportCase
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

    def test_set_prep_stage_allows_intentional_step_back_and_blocks_cancelled(self):
        order = Order.objects.create(
            id='STW-PREP-BACK',
            customer=self.student,
            customer_name=self.student.full_name,
            email=self.student.email,
            phone=self.student.phone,
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 30.0, 'qty': 1}],
            subtotal=Decimal('30.00'),
            fee=Decimal('1.50'),
            total=Decimal('31.50'),
            pickup_day='2026-11-20',
            prep_stage='accepted',
            prep_at={'accepted': 1700000000000},
            payment_status='paid',
            settlement_status='pending',
        )
        self.client.force_authenticate(user=self.vendor_user)
        r1 = self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'shopping'}, format='json')
        self.assertEqual(r1.status_code, 200)
        r2 = self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'cooking'}, format='json')
        self.assertEqual(r2.status_code, 200)
        # Intentional: vendor can step back to correct an accidental tap
        r3 = self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'shopping'}, format='json')
        self.assertEqual(r3.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.prep_stage, 'shopping')
        self.assertIn('accepted', order.prep_at)
        self.assertIn('shopping', order.prep_at)
        self.assertIn('cooking', order.prep_at)

        # Cancelled order cannot change prep stage
        order.cancelled_at = timezone.now()
        order.save(update_fields=['cancelled_at'])
        r4 = self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'ready'}, format='json')
        self.assertEqual(r4.status_code, 400)


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

        # Race 4: verify_payment_view racing cancel_order_view on PostgreSQL threads
        from api.models import AuditEntry
        vc_order = Order.objects.create(
            id='STW-PG-RACE4', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', prep_stage='accepted',
            payment_reference='PSK-PG-RACE4',
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )
        verify_entered_http = threading.Event()
        cancel_finished = threading.Event()

        def _fake_pg_verify_get(*args, **kwargs):
            verify_entered_http.set()
            cancel_finished.wait(timeout=5)
            resp = MagicMock(ok=True)
            resp.json.return_value = {
                'status': True,
                'data': {'status': 'success', 'reference': 'PSK-PG-RACE4', 'currency': 'GHS', 'amount': 2100},
            }
            return resp

        def _verify_mid_http():
            c = APIClient()
            c.force_authenticate(user=self.student)
            r = c.post('/api/payments/verify/', {'orderId': vc_order.id, 'reference': 'PSK-PG-RACE4'}, format='json')
            return ('verify', r.status_code, r.data)

        def _cancel_mid_http():
            verify_entered_http.wait(timeout=5)
            c = APIClient()
            c.force_authenticate(user=self.student)
            r = c.post(f'/api/orders/{vc_order.id}/cancel/', {}, format='json')
            cancel_finished.set()
            return ('cancel', r.status_code, r.data)

        with override_settings(PAYSTACK_SECRET_KEY='sk_test_pg_race'):
            with patch('api.views.http_requests.get', side_effect=_fake_pg_verify_get):
                t1_res = {}
                t2_res = {}

                def _run_t(target_fn, store, k):
                    connections.close_all()
                    try:
                        store[k] = target_fn()
                    finally:
                        connections.close_all()

                th1 = threading.Thread(target=_run_t, args=(_verify_mid_http, t1_res, 'res'))
                th2 = threading.Thread(target=_run_t, args=(_cancel_mid_http, t2_res, 'res'))
                th1.start()
                th2.start()
                th1.join(timeout=15)
                th2.join(timeout=15)

        self.assertEqual(t2_res['res'][1], 200, t2_res['res'])
        self.assertEqual(t1_res['res'][1], 400, t1_res['res'])
        self.assertIn('refund', t1_res['res'][2].get('message', '').lower())
        vc_order.refresh_from_db()
        self.assertIsNotNone(vc_order.cancelled_at)
        self.assertIsNotNone(vc_order.paid_at)
        self.assertEqual(vc_order.payment_status, 'refund_pending')
        self.assertTrue(
            AuditEntry.objects.filter(entity_id=vc_order.id, action='payment_received_after_cancel').exists()
        )

        # Uncoordinated barrier race between verify and cancel
        bar_order = Order.objects.create(
            id='STW-PG-RACE5', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', prep_stage='accepted',
            payment_reference='PSK-PG-RACE5',
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )
        ok_resp = MagicMock(ok=True)
        ok_resp.json.return_value = {
            'status': True,
            'data': {'status': 'success', 'reference': 'PSK-PG-RACE5', 'currency': 'GHS', 'amount': 2100},
        }
        with override_settings(PAYSTACK_SECRET_KEY='sk_test_pg_race'):
            with patch('api.views.http_requests.get', return_value=ok_resp):
                def _verify_bar():
                    c = APIClient()
                    c.force_authenticate(user=self.student)
                    return ('verify', c.post('/api/payments/verify/', {'orderId': bar_order.id, 'reference': 'PSK-PG-RACE5'}, format='json').status_code)

                def _cancel_bar():
                    c = APIClient()
                    c.force_authenticate(user=self.student)
                    return ('cancel', c.post(f'/api/orders/{bar_order.id}/cancel/', {}, format='json').status_code)

                bar_results = dict(_race([_verify_bar, _cancel_bar]))

        self.assertEqual(bar_results['cancel'], 200, bar_results)
        self.assertIn(bar_results['verify'], (200, 400), bar_results)
        bar_order.refresh_from_db()
        self.assertIsNotNone(bar_order.cancelled_at)
        self.assertIsNotNone(bar_order.paid_at)
        self.assertIn(bar_order.payment_status, ('refund_pending', 'refunded'))

        # Race 6: Concurrent prep stage updates preserve all prep_at keys (no lost update)
        prep_race_order = Order.objects.create(
            id='STW-PG-RACE6', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='paid', prep_stage='accepted', prep_at={'accepted': 1700000000000},
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )

        def _prep_stage(stage_val):
            c = APIClient()
            c.force_authenticate(user=self.vendor_user)
            return c.post(f'/api/orders/{prep_race_order.id}/prep/', {'stage': stage_val}, format='json').status_code

        race6_statuses = _race([lambda: _prep_stage('shopping'), lambda: _prep_stage('cooking')])
        self.assertEqual(race6_statuses, [200, 200], race6_statuses)
        prep_race_order.refresh_from_db()
        self.assertIn('shopping', prep_race_order.prep_at)
        self.assertIn('cooking', prep_race_order.prep_at)

        # Race 7: Student cancel vs vendor set_prep_stage race
        cp_order = Order.objects.create(
            id='STW-PG-RACE7', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='paid', prep_stage='accepted', prep_at={'accepted': 1700000000000},
            lines=[{'mealId': self.meal_z.id, 'qty': 1}],
        )

        def _cust_cancel_cp():
            c = APIClient()
            c.force_authenticate(user=self.student)
            return ('cancel', c.post(f'/api/orders/{cp_order.id}/cancel/', {}, format='json').status_code)

        def _vend_prep_cp():
            c = APIClient()
            c.force_authenticate(user=self.vendor_user)
            return ('prep', c.post(f'/api/orders/{cp_order.id}/prep/', {'stage': 'cooking'}, format='json').status_code)

        cp_results = dict(_race([_cust_cancel_cp, _vend_prep_cp]))
        self.assertEqual(sorted(cp_results.values()), [200, 400], cp_results)
        cp_order.refresh_from_db()
        if cp_results['cancel'] == 200:
            self.assertIsNotNone(cp_order.cancelled_at)
            self.assertEqual(cp_order.prep_stage, 'accepted')
        else:
            self.assertIsNone(cp_order.cancelled_at)
            self.assertEqual(cp_order.prep_stage, 'cooking')


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
        from api.models import AuditEntry
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
        self.assertIsNotNone(o_can.cancelled_at)
        self.assertNotEqual(o_can.payment_status, 'paid')
        self.assertEqual(o_can.payment_status, 'refund_pending')
        self.assertIsNotNone(o_can.paid_at)
        self.assertEqual(o_can.payment_reference, 'PSK-CAN-1')
        self.assertTrue(
            AuditEntry.objects.filter(
                entity_id=o_can.id, action='payment_received_after_cancel'
            ).exists()
        )

        # Already refunded order remains 'refunded' idempotently
        o_ref = Order.objects.create(
            id='STW-ATOM-REF', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='refunded', cancelled_at=now, paid_at=now,
        )
        _mark_order_paid(o_ref, 'paystack_webhook', 'PSK-REF-1')
        o_ref.refresh_from_db()
        self.assertEqual(o_ref.payment_status, 'refunded')

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


class IDORAndSerializerExposureTests(TestCase):
    """
    FIN-12: Prevent cross-user push endpoint hijacking, redact customer email and Paystack
    reference from vendor order views, and declare explicit read_only_fields on read serializers.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student_a = User.objects.create_user(
            email='fin12.a@st.knust.edu.gh', password='Password123',
            full_name='Fin12 Student A', reference_id='20891201', phone='0249120001',
            hall='Unity Hall', verified=True, role='customer', account_type='customer',
        )
        cls.student_b = User.objects.create_user(
            email='fin12.b@st.knust.edu.gh', password='Password123',
            full_name='Fin12 Student B', reference_id='20891202', phone='0249120002',
            hall='Unity Hall', verified=True, role='customer', account_type='customer',
        )
        cls.vendor_user = User.objects.create_user(
            email='fin12.vendor@st.knust.edu.gh', password='Password123',
            full_name='Fin12 Vendor', reference_id='20891203', phone='0249120003',
            hall='Unity Hall', verified=True, role='vendor', account_type='vendor', is_vendor=True,
        )
        cls.admin = User.objects.create_superuser(
            email='fin12.admin@st.knust.edu.gh', password='AdminPassword123',
            full_name='Fin12 Admin',
        )
        cls.vendor = Vendor.objects.create(
            id='v_fin12', user=cls.vendor_user, name='Fin12 Kitchen',
            hall='Unity Hall', open=True, active=True,
        )
        cls.order = Order.objects.create(
            id='STW-FIN12-1', customer=cls.student_a, email=cls.student_a.email,
            vendor=cls.vendor, vendor_name=cls.vendor.name,
            subtotal=Decimal('30.00'), fee=Decimal('1.50'), total=Decimal('31.50'),
            payment_status='paid', payment_reference='PSK-FIN12-SECRET', handoff_code='654321',
        )

    def setUp(self):
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()

    def test_push_subscription_cannot_be_hijacked_by_another_user(self):
        endpoint = 'https://push.example.com/sub/fin12-abc'
        self.client.force_authenticate(user=self.student_a)
        r1 = self.client.post('/api/notifications/subscribe/', {
            'endpoint': endpoint, 'keys': {'p256dh': 'k1', 'auth': 'a1'},
        }, format='json')
        self.assertEqual(r1.status_code, 201)

        self.client.force_authenticate(user=self.student_b)
        r2 = self.client.post('/api/notifications/subscribe/', {
            'endpoint': endpoint, 'keys': {'p256dh': 'evil', 'auth': 'evil'},
        }, format='json')
        self.assertEqual(r2.status_code, 409)
        sub = PushSubscription.objects.get(endpoint=endpoint)
        self.assertEqual(str(sub.user_id), str(self.student_a.id))
        self.assertEqual(sub.keys.get('p256dh'), 'k1')

    def test_order_serializer_redacts_customer_email_and_payment_ref_from_vendor_and_read_only_fields(self):
        from api import serializers as api_serializers

        # Vendor views order -> email, payment.reference, handoffCode must be None
        self.client.force_authenticate(user=self.vendor_user)
        r_v_detail = self.client.get(f'/api/orders/{self.order.id}/')
        self.assertEqual(r_v_detail.status_code, 200)
        self.assertIsNone(r_v_detail.data['email'])
        self.assertIsNone(r_v_detail.data['payment']['reference'])
        self.assertIsNone(r_v_detail.data['handoffCode'])

        r_v_list = self.client.get('/api/orders/?as=vendor')
        self.assertEqual(r_v_list.status_code, 200)
        self.assertEqual(len(r_v_list.data), 1)
        self.assertIsNone(r_v_list.data[0]['email'])
        self.assertIsNone(r_v_list.data[0]['payment']['reference'])

        # Customer owner still sees their email, payment.reference, and handoffCode
        self.client.force_authenticate(user=self.student_a)
        r_c = self.client.get(f'/api/orders/{self.order.id}/')
        self.assertEqual(r_c.status_code, 200)
        self.assertEqual(r_c.data['email'], self.student_a.email)
        self.assertEqual(r_c.data['payment']['reference'], 'PSK-FIN12-SECRET')
        self.assertEqual(r_c.data['handoffCode'], '654321')

        # Platform admin also still sees email and payment.reference
        self.client.force_authenticate(user=self.admin)
        r_a = self.client.get(f'/api/orders/{self.order.id}/')
        self.assertEqual(r_a.status_code, 200)
        self.assertEqual(r_a.data['email'], self.student_a.email)
        self.assertEqual(r_a.data['payment']['reference'], 'PSK-FIN12-SECRET')

        # All read ModelSerializers explicitly declare read_only_fields covering Meta.fields
        for ser_cls in (
            api_serializers.UserSerializer,
            api_serializers.VendorSerializer,
            api_serializers.MealSerializer,
            api_serializers.OrderSerializer,
            api_serializers.ReviewSerializer,
            api_serializers.ComplianceSerializer,
            api_serializers.PayoutBatchSerializer,
            api_serializers.SupportCaseSerializer,
            api_serializers.AuditEntrySerializer,
            api_serializers.AdminUserSerializer,
        ):
            ro = getattr(ser_cls.Meta, 'read_only_fields', ())
            self.assertEqual(set(ro), set(ser_cls.Meta.fields), f'{ser_cls.__name__} missing read_only_fields')


class AuthAndEmailBypassTests(TestCase):
    """
    FIN-13: JWT tokens must be revocable via /api/auth/logout/, campus email normalization must
    block +aliases, consecutive/edge dots, percent/control chars, homoglyphs, and subdomains,
    and verify-email must not enumerate missing accounts via 404.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='fin13.student@st.knust.edu.gh', password='Password123',
            full_name='Fin13 Student', reference_id='20891301', phone='0249130001',
            hall='Unity Hall', verified=True, role='customer', account_type='customer',
        )

    def setUp(self):
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()

    def test_logout_revokes_jwt_while_new_token_still_works(self):
        token1 = generate_jwt_token(self.student)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token1}')
        r_me1 = self.client.get('/api/auth/me/')
        self.assertEqual(r_me1.status_code, 200)

        r_logout = self.client.post('/api/auth/logout/', {}, format='json')
        self.assertEqual(r_logout.status_code, 200)
        self.assertEqual(r_logout.data, {'ok': True})

        # Revoked token is immediately rejected
        r_after = self.client.get('/api/auth/me/')
        self.assertEqual(r_after.status_code, 401)

        # Fresh login / token still works normally
        token2 = generate_jwt_token(self.student)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token2}')
        r_me2 = self.client.get('/api/auth/me/')
        self.assertEqual(r_me2.status_code, 200)

    def test_clean_knust_email_rejects_plus_dots_control_homoglyphs_and_subdomains(self):
        from rest_framework.exceptions import ValidationError as DRFValidationError
        from api.validators import clean_knust_email

        bad_emails = [
            'kofi+alias@st.knust.edu.gh',
            'kofi%00@st.knust.edu.gh',
            '.kofi@st.knust.edu.gh',
            'kofi.@st.knust.edu.gh',
            'kofi..b@st.knust.edu.gh',
            'k\u043efi@st.knust.edu.gh',
            'kofi@sub.st.knust.edu.gh',
        ]
        for bad in bad_emails:
            with self.assertRaises(DRFValidationError, msg=f'Expected rejection for {bad!r}'):
                clean_knust_email(bad)

        self.assertEqual(clean_knust_email(' Kofi.Boateng-1@ST.KNUST.EDU.GH '), 'kofi.boateng-1@st.knust.edu.gh')
        self.assertEqual(clean_knust_email('admin_ops@st.knust.edu.gh'), 'admin_ops@st.knust.edu.gh')

    def test_verify_email_does_not_enumerate_unknown_accounts(self):
        r = self.client.post('/api/auth/verify-email/', {
            'email': 'nonexistent.fin13@st.knust.edu.gh',
            'code': '123456',
        }, format='json')
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.data.get('message'), 'Invalid or expired code')


class SettingsAndAdminHardeningTests(TestCase):
    """
    FIN-14: seed_data must refuse --demo and weak passwords in production without clobbering
    existing admin credentials, Django /admin/ must obey is_admin + verified, and responses
    must include Content-Security-Policy and Permissions-Policy headers.
    """

    def test_seed_data_refuses_demo_or_weak_default_password_in_prod_and_preserves_existing_admin_password(self):
        import os
        from django.core.management import CommandError, call_command

        with override_settings(DEBUG=False):
            with self.assertRaises(CommandError):
                call_command('seed_data', demo=True)

            env_copy = os.environ.copy()
            env_copy.pop('SEED_ADMIN_PASSWORD', None)
            with patch.dict(os.environ, env_copy, clear=True):
                with self.assertRaises(CommandError):
                    call_command('seed_data')

        existing = User.objects.create_user(
            email='admin@st.knust.edu.gh', password='CustomStrongPass99',
            full_name='Existing Ops Admin', reference_id='20819999',
            phone='0257059777', hall='Commercial Area',
            role='admin', account_type='admin',
            is_admin=True, is_staff=True, is_superuser=True, verified=True,
        )
        with override_settings(DEBUG=True):
            call_command('seed_data')
        existing.refresh_from_db()
        self.assertTrue(existing.check_password('CustomStrongPass99'))
        self.assertFalse(existing.check_password('admin1234'))

    def test_django_admin_site_requires_is_admin_and_verified(self):
        from types import SimpleNamespace
        from django.contrib import admin
        import stew_server.urls  # noqa: F401

        staff_only = SimpleNamespace(
            is_authenticated=True, is_active=True,
            is_staff=True, is_superuser=True, is_admin=False, verified=True,
        )
        unverified_admin = SimpleNamespace(
            is_authenticated=True, is_active=True,
            is_staff=True, is_superuser=True, is_admin=True, verified=False,
        )
        platform_admin = SimpleNamespace(
            is_authenticated=True, is_active=True,
            is_staff=True, is_superuser=False, is_admin=True, verified=True,
        )
        self.assertFalse(admin.site.has_permission(SimpleNamespace(user=staff_only)))
        self.assertFalse(admin.site.has_permission(SimpleNamespace(user=unverified_admin)))
        self.assertTrue(admin.site.has_permission(SimpleNamespace(user=platform_admin)))

    def test_security_headers_csp_and_permissions_policy_present(self):
        r = self.client.get('/api/vendors/')
        self.assertEqual(r.status_code, 200)
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertTrue(r.headers.get('Permissions-Policy'))


class PaidAfterCancelOrphanPreventionTests(TestCase):
    """
    REL-01: Paystack confirmation after cancellation (cancel then webhook,
    cancel then verify, duplicate webhooks) must record payment reception,
    transition the order to refund_pending under row lock with AuditEntry,
    and return an explicit non-200 error on verify_payment_view.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='pac.student@st.knust.edu.gh', password='Password123',
            full_name='PAC Student', reference_id='20892001', phone='0249200001',
            hall='Unity Hall', verified=True,
        )
        cls.vendor_user = User.objects.create_user(
            email='pac.vendor@st.knust.edu.gh', password='Password123',
            full_name='PAC Vendor', reference_id='20892002', phone='0249200002',
            hall='Unity Hall', verified=True, is_vendor=True, role='vendor', account_type='vendor',
        )
        cls.vendor = Vendor.objects.create(
            id='v_pac1', user=cls.vendor_user, name='PAC Kitchen',
            hall='Unity Hall', open=True, active=True,
        )
        cls.meal = Meal.objects.create(
            id='m_pac1', vendor=cls.vendor, name='PAC Jollof',
            price=Decimal('20.00'), left=10, on=True,
        )

    def setUp(self):
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()

    def _signed_webhook(self, payload_dict, secret='sk_test_pac_sec'):
        raw = json.dumps(payload_dict).encode('utf-8')
        sig = hmac.new(secret.encode('utf-8'), raw, hashlib.sha512).hexdigest()
        return self.client.post(
            '/api/payments/webhook/',
            data=raw,
            content_type='application/json',
            HTTP_X_PAYSTACK_SIGNATURE=sig,
        )

    @override_settings(PAYSTACK_SECRET_KEY='sk_test_pac_sec')
    def test_cancel_then_webhook_and_duplicate_webhook_are_recorded_and_idempotent(self):
        from api.models import AuditEntry
        order = Order.objects.create(
            id='STW-PAC-WH1', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', payment_reference='PSK-PAC-WH1',
            lines=[{'mealId': self.meal.id, 'qty': 1}],
        )
        self.client.force_authenticate(user=self.student)
        r_can = self.client.post(f'/api/orders/{order.id}/cancel/', {}, format='json')
        self.assertEqual(r_can.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.payment_status, 'cancelled')
        self.assertIsNotNone(order.cancelled_at)

        self.client.credentials()
        mock_resp = MagicMock(ok=True)
        mock_resp.json.return_value = {
            'status': True,
            'data': {'status': 'success', 'reference': 'PSK-PAC-WH1', 'currency': 'GHS', 'amount': 2100},
        }
        payload = {
            'event': 'charge.success',
            'data': {'status': 'success', 'reference': 'PSK-PAC-WH1', 'currency': 'GHS', 'amount': 2100},
        }
        with patch('api.views.http_requests.get', return_value=mock_resp) as mock_get:
            r_wh1 = self._signed_webhook(payload)
            self.assertEqual(r_wh1.status_code, 200)
            self.assertEqual(mock_get.call_count, 1)

            order.refresh_from_db()
            self.assertEqual(order.payment_status, 'refund_pending')
            self.assertIsNotNone(order.cancelled_at)
            self.assertIsNotNone(order.paid_at)
            first_paid_at = order.paid_at

            audits = AuditEntry.objects.filter(entity_id=order.id, action='payment_received_after_cancel')
            self.assertEqual(audits.count(), 1)
            audit = audits.first()
            self.assertEqual(audit.extra.get('reference'), 'PSK-PAC-WH1')
            self.assertEqual(audit.extra.get('amount'), '21.00')

            # Duplicate webhook must be idempotent (no second verify API call, no second audit)
            r_wh2 = self._signed_webhook(payload)
            self.assertEqual(r_wh2.status_code, 200)
            self.assertEqual(mock_get.call_count, 1)
            order.refresh_from_db()
            self.assertEqual(order.payment_status, 'refund_pending')
            self.assertEqual(order.paid_at, first_paid_at)
            self.assertEqual(
                AuditEntry.objects.filter(entity_id=order.id, action='payment_received_after_cancel').count(),
                1,
            )

    @override_settings(PAYSTACK_SECRET_KEY='sk_test_pac_sec')
    def test_cancel_then_verify_returns_error_and_marks_refund_pending(self):
        from api.models import AuditEntry
        order = Order.objects.create(
            id='STW-PAC-VER1', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='cancelled', cancelled_at=timezone.now(),
            payment_reference='PSK-PAC-VER1',
            lines=[{'mealId': self.meal.id, 'qty': 1}],
        )
        mock_resp = MagicMock(ok=True)
        mock_resp.json.return_value = {
            'status': True,
            'data': {'status': 'success', 'reference': 'PSK-PAC-VER1', 'currency': 'GHS', 'amount': 2100},
        }
        self.client.force_authenticate(user=self.student)
        with patch('api.views.http_requests.get', return_value=mock_resp):
            r = self.client.post(
                '/api/payments/verify/',
                {'orderId': order.id, 'reference': 'PSK-PAC-VER1'},
                format='json',
            )
        self.assertEqual(r.status_code, 400)
        msg = r.data.get('message', '').lower()
        self.assertIn('cancelled', msg)
        self.assertIn('refund pending', msg.replace('refund is pending', 'refund pending'))
        self.assertEqual(r.data.get('code'), 'refund_pending')

        order.refresh_from_db()
        self.assertEqual(order.payment_status, 'refund_pending')
        self.assertIsNotNone(order.paid_at)
        self.assertEqual(
            AuditEntry.objects.filter(entity_id=order.id, action='payment_received_after_cancel').count(),
            1,
        )

    @override_settings(DEBUG=True, PAYSTACK_ALLOW_MOCK=True, PAYSTACK_SECRET_KEY='')
    def test_init_payment_refuses_cancelled_and_refund_states(self):
        self.client.force_authenticate(user=self.student)
        for idx, (pstatus, is_cancelled) in enumerate([
            ('cancelled', True),
            ('refund_pending', True),
            ('refunded', True),
            ('pending', True),
        ]):
            o = Order.objects.create(
                id=f'STW-PAC-INIT{idx}', customer=self.student, email=self.student.email,
                vendor=self.vendor, vendor_name=self.vendor.name,
                subtotal=Decimal('10.00'), fee=Decimal('0.50'), total=Decimal('10.50'),
                payment_status=pstatus,
                cancelled_at=timezone.now() if is_cancelled else None,
            )
            r = self.client.post('/api/payments/initialize/', {'orderId': o.id}, format='json')
            self.assertEqual(r.status_code, 400, f"Expected 400 for status={pstatus}, cancelled={is_cancelled}")


class ProxyClientIpAndCampusNatRateLimitTests(TestCase):
    """
    REL-02: Right-to-left X-Forwarded-For extraction controlled by
    TRUSTED_PROXY_COUNT (default 0 = REMOTE_ADDR only), generous per-IP NAT
    ceilings so shared campus Wi-Fi does not lock out students, and strict
    per-email OTP brute-force lockout enforcement.
    """

    def setUp(self):
        from django.core.cache import cache
        _RATE_LIMIT_CACHE.clear()
        cache.clear()
        self.client = APIClient()

    def test_get_client_ip_respects_trusted_proxy_count_right_to_left(self):
        from django.test import RequestFactory
        from api.security import get_client_ip

        rf = RequestFactory()
        self.assertEqual(getattr(settings, 'TRUSTED_PROXY_COUNT', None), 0)

        # Count=0 (default): spoofed XFF must be completely ignored
        req0 = rf.get(
            '/api/auth/register/',
            REMOTE_ADDR='196.201.1.10',
            HTTP_X_FORWARDED_FOR='1.2.3.4, 5.6.7.8',
        )
        with override_settings(TRUSTED_PROXY_COUNT=0):
            self.assertEqual(get_client_ip(req0), '196.201.1.10')

        # Count=1: takes right-most hop added by single trusted proxy, ignoring spoofed left-most IP
        req1 = rf.get(
            '/api/auth/register/',
            REMOTE_ADDR='10.0.0.1',
            HTTP_X_FORWARDED_FOR='1.1.1.1, 198.51.100.25',
        )
        with override_settings(TRUSTED_PROXY_COUNT=1):
            self.assertEqual(get_client_ip(req1), '198.51.100.25')

        # Count=2: takes 2nd hop from right (CDN + LB/proxy), ignoring spoofed left-most IP
        req2 = rf.get(
            '/api/auth/register/',
            REMOTE_ADDR='10.0.0.1',
            HTTP_X_FORWARDED_FOR='1.1.1.1, 198.51.100.25, 10.0.0.5',
        )
        with override_settings(TRUSTED_PROXY_COUNT=2):
            self.assertEqual(get_client_ip(req2), '198.51.100.25')

        # Malformed / short XFF falls back safely to REMOTE_ADDR
        req_bad = rf.get(
            '/api/auth/register/',
            REMOTE_ADDR='196.201.1.99',
            HTTP_X_FORWARDED_FOR='not-an-ip, 10.0.0.5',
        )
        with override_settings(TRUSTED_PROXY_COUNT=2):
            self.assertEqual(get_client_ip(req_bad), '196.201.1.99')

        req_short = rf.get(
            '/api/auth/register/',
            REMOTE_ADDR='196.201.1.98',
            HTTP_X_FORWARDED_FOR='198.51.100.25',
        )
        with override_settings(TRUSTED_PROXY_COUNT=2):
            self.assertEqual(get_client_ip(req_short), '196.201.1.98')

    def test_campus_nat_many_distinct_emails_not_blocked_while_single_email_otp_still_locks(self):
        # 25 different students registering & requesting password reset from the same campus NAT IP
        for i in range(25):
            email = f'nat.student{i}@st.knust.edu.gh'
            r_reg = self.client.post(
                '/api/auth/register/',
                {
                    'fullName': f'NAT Student {i}',
                    'email': email,
                    'referenceId': f'2091{i:04d}',
                    'phone': f'0249{i:06d}',
                    'accountType': 'customer',
                    'password': 'Password123',
                },
                format='json',
                REMOTE_ADDR='196.201.55.10',
            )
            self.assertEqual(r_reg.status_code, 201, f'Student {i} reg failed: {r_reg.data}')

            r_fp = self.client.post(
                '/api/auth/forgot-password/',
                {'email': email},
                format='json',
                REMOTE_ADDR='196.201.55.10',
            )
            self.assertEqual(r_fp.status_code, 200, f'Student {i} forgot-password failed: {r_fp.data}')

        # Single email repeated OTP failures (6th try) still hits 429 and burns OTP regardless of rotating IP/XFF
        target = User.objects.get(email='nat.student0@st.knust.edu.gh')
        target.verification_code_hash = hash_token('765432')
        target.verification_code_expires = timezone.now() + timedelta(minutes=15)
        target.save(update_fields=['verification_code_hash', 'verification_code_expires'])

        for i in range(5):
            r_bad = self.client.post(
                '/api/auth/verify-email/',
                {'email': target.email, 'code': '000000'},
                format='json',
                REMOTE_ADDR=f'198.51.100.{i + 1}',
                HTTP_X_FORWARDED_FOR=f'203.0.113.{i + 1}',
            )
            self.assertEqual(r_bad.status_code, 400)

        r_lock = self.client.post(
            '/api/auth/verify-email/',
            {'email': target.email, 'code': '765432'},
            format='json',
            REMOTE_ADDR='198.51.100.99',
            HTTP_X_FORWARDED_FOR='203.0.113.99',
        )
        self.assertEqual(r_lock.status_code, 429)
        target.refresh_from_db()
        self.assertEqual(target.verification_code_hash, '')


class RateLimitBucketCleanupAndScaleTests(TestCase):
    """
    REL-03: RateLimitBucket must bound key lengths safely without breaking prefixes,
    purge expired rate-limit and revocation buckets in batches via
    `manage.py cleanup_rate_limits`, preserve active revocations within the
    configured JWT lifetime, and sustain fast PK lookups at 100k rows.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='bucket.student@st.knust.edu.gh', password='Password123',
            full_name='Bucket Student', reference_id='20893001', phone='0249300001',
            hall='Unity Hall', verified=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_cleanup_rate_limits_removes_stale_keeps_fresh_and_bounds_keys(self):
        from django.core.management import call_command
        from api.models import RateLimitBucket
        from api.security import check_rate_limit, is_jwt_revoked, revoke_jwt_token

        now = timezone.now()

        # Long keys (> 255 chars) must be hashed deterministically with preserved prefixes
        long_rl_key = 'rl_' + ('x' * 400)
        self.assertTrue(check_rate_limit(long_rl_key, limit=2, window_seconds=60))
        rl_row = RateLimitBucket.objects.get()
        self.assertLessEqual(len(rl_row.key), 255)
        self.assertTrue(rl_row.key.startswith('rl_sha256_'))

        long_jti_payload = {'jti': 'j_' + ('y' * 400)}
        revoke_jwt_token('dummy-tok', payload=long_jti_payload)
        self.assertTrue(is_jwt_revoked('dummy-tok', payload=long_jti_payload))
        self.assertEqual(RateLimitBucket.objects.filter(key__startswith='jwt_revoked_').count(), 1)
        RateLimitBucket.objects.all().delete()

        # Seed stale + fresh rate-limit rows
        for i in range(30):
            RateLimitBucket.objects.create(key=f'stale_rl_{i}', count=1, window_start=now - timedelta(hours=3))
        RateLimitBucket.objects.create(key='fresh_rl', count=1, window_start=now - timedelta(minutes=20))

        # Revoke a valid token and create one stale revocation row older than lifetime + margin
        revoked_tok = generate_jwt_token(self.student)
        revoke_jwt_token(revoked_tok)
        RateLimitBucket.objects.create(
            key='jwt_revoked_expired_old_jti',
            count=1,
            window_start=now - timedelta(hours=20),
        )

        # Also create an expired JWT that was revoked long ago
        import jwt as pyjwt
        old_now = now - timedelta(hours=20)
        expired_tok = pyjwt.encode(
            {
                'sub': str(self.student.id),
                'jti': 'expired_jti_for_cleanup',
                'role': self.student.role,
                'iss': 'stew',
                'iat': int(old_now.timestamp()),
                'exp': int((old_now + timedelta(hours=1)).timestamp()),
            },
            settings.SECRET_KEY,
            algorithm='HS256',
        )
        RateLimitBucket.objects.create(
            key='jwt_revoked_expired_jti_for_cleanup',
            count=1,
            window_start=old_now,
        )

        with override_settings(JWT_ACCESS_TOKEN_LIFETIME_HOURS=12):
            call_command('cleanup_rate_limits', batch_size=10, margin_seconds=3600)

        self.assertEqual(RateLimitBucket.objects.filter(key__startswith='stale_rl_').count(), 0)
        self.assertTrue(RateLimitBucket.objects.filter(key='fresh_rl').exists())
        self.assertFalse(RateLimitBucket.objects.filter(key='jwt_revoked_expired_old_jti').exists())
        self.assertFalse(RateLimitBucket.objects.filter(key='jwt_revoked_expired_jti_for_cleanup').exists())

        # Active revoked token MUST stay in DB and MUST still be rejected with 401
        self.assertTrue(is_jwt_revoked(revoked_tok))
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {revoked_tok}')
        self.assertEqual(self.client.get('/api/auth/me/').status_code, 401)

        # Expired token whose revocation row was cleaned is STILL rejected via exp
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {expired_tok}')
        self.assertEqual(self.client.get('/api/auth/me/').status_code, 401)

    def test_100k_rows_is_jwt_revoked_lookup_and_batched_cleanup_performance(self):
        import time
        from django.core.management import call_command
        from api.models import RateLimitBucket
        from api.security import is_jwt_revoked, revoke_jwt_token

        stale_ts = timezone.now() - timedelta(hours=5)
        for offset in range(0, 100_000, 10_000):
            RateLimitBucket.objects.bulk_create(
                [
                    RateLimitBucket(key=f'perf_rl_{offset + j}', count=1, window_start=stale_ts)
                    for j in range(10_000)
                ],
                batch_size=5_000,
            )

        revoked_tok = generate_jwt_token(self.student)
        fresh_tok = generate_jwt_token(self.student)
        revoke_jwt_token(revoked_tok)

        t0 = time.perf_counter()
        rev_hit = is_jwt_revoked(revoked_tok)
        rev_miss = is_jwt_revoked(fresh_tok)
        elapsed = time.perf_counter() - t0

        self.assertTrue(rev_hit)
        self.assertFalse(rev_miss)
        self.assertLess(elapsed, 0.1, f'is_jwt_revoked took {elapsed:.4f}s at 100k rows')

        call_command('cleanup_rate_limits', batch_size=10_000, margin_seconds=3600)
        self.assertEqual(RateLimitBucket.objects.filter(key__startswith='perf_rl_').count(), 0)
        self.assertTrue(is_jwt_revoked(revoked_tok))


class EscrowReleaseGuardTests(TestCase):
    """
    REL-05: _release_escrow must refuse unpaid, cancelled, and already-released
    orders directly by raising EscrowReleaseError (ValidationError subclass -> 400),
    and both /collected/ and /complete/ endpoints must return 400 (never 500 or 200).
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='escg.student@st.knust.edu.gh', password='Password123',
            full_name='Escrow Guard Student', reference_id='20894001', phone='0249400001',
            hall='Unity Hall', verified=True,
        )
        cls.vendor_user = User.objects.create_user(
            email='escg.vendor@st.knust.edu.gh', password='Password123',
            full_name='Escrow Guard Vendor', reference_id='20894002', phone='0249400002',
            hall='Unity Hall', verified=True, is_vendor=True, role='vendor', account_type='vendor',
        )
        cls.vendor = Vendor.objects.create(
            id='v_escg1', user=cls.vendor_user, name='Escrow Guard Kitchen',
            hall='Unity Hall', open=True, active=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def _make_orders(self, prefix):
        now = timezone.now()
        o_pending = Order.objects.create(
            id=f'{prefix}-PEND', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='pending', settlement_status='pending',
            prep_stage='ready', handoff_code='112233',
        )
        o_cancelled = Order.objects.create(
            id=f'{prefix}-CANC', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='cancelled', settlement_status='pending',
            cancelled_at=now, prep_stage='ready', handoff_code='112233',
        )
        o_released = Order.objects.create(
            id=f'{prefix}-RELS', customer=self.student, email=self.student.email,
            vendor=self.vendor, vendor_name=self.vendor.name,
            subtotal=Decimal('20.00'), fee=Decimal('1.00'), total=Decimal('21.00'),
            payment_status='released', settlement_status='released',
            paid_at=now, collected_at=now, collected_via='student_confirmed',
            settlement_released_at=now, settlement_net=Decimal('20.00'),
            prep_stage='collected', handoff_code='112233',
        )
        return o_pending, o_cancelled, o_released

    def test_release_escrow_direct_calls_raise_on_pending_cancelled_and_released(self):
        from api.views import EscrowReleaseError, _release_escrow

        for o in self._make_orders('STW-DIR'):
            orig_status = o.payment_status
            orig_settlement = o.settlement_status
            orig_collected_via = o.collected_via
            with self.assertRaises(EscrowReleaseError, msg=f'Expected EscrowReleaseError on {o.id}'):
                _release_escrow(o, 'handoff_code', self.vendor_user.email)
            o.refresh_from_db()
            self.assertEqual(o.payment_status, orig_status)
            self.assertEqual(o.settlement_status, orig_settlement)
            self.assertEqual(o.collected_via, orig_collected_via)

    def test_collected_and_complete_endpoints_return_400_on_pending_cancelled_and_released(self):
        o_pend, o_canc, o_rels = self._make_orders('STW-EP')

        for o in (o_pend, o_canc, o_rels):
            self.client.force_authenticate(user=self.student)
            r_col = self.client.post(f'/api/orders/{o.id}/collected/', {}, format='json')
            self.assertEqual(r_col.status_code, 400, f'/collected/ on {o.id} gave {r_col.status_code}')

            self.client.force_authenticate(user=self.vendor_user)
            r_cmp = self.client.post(f'/api/orders/{o.id}/complete/', {'code': '112233'}, format='json')
            self.assertEqual(r_cmp.status_code, 400, f'/complete/ on {o.id} gave {r_cmp.status_code}')

        o_pend.refresh_from_db()
        o_canc.refresh_from_db()
        o_rels.refresh_from_db()
        self.assertEqual(o_pend.payment_status, 'pending')
        self.assertIsNone(o_pend.collected_at)
        self.assertEqual(o_canc.payment_status, 'cancelled')
        self.assertIsNone(o_canc.collected_at)
        self.assertEqual(o_rels.collected_via, 'student_confirmed')


from rest_framework.test import APIClient
from django.test import TestCase as _DjangoTestCase


class SupportCaseAuditSnapshotTests(_DjangoTestCase):
    """WP6: Support case resolution must persist a full AuditEntry snapshot before deleting the row."""

    def test_refund_and_dismiss_write_full_snapshot_audit_before_delete_and_block_double_resolve(self):
        from datetime import datetime
        from decimal import Decimal
        from api.models import AuditEntry, Order, PayoutBatch, SupportCase, User, Vendor
        from api.security import generate_jwt_token

        client = APIClient()

        admin = User.objects.create_user(
            email='sc_admin@st.knust.edu.gh',
            password='Password123!',
            role='admin',
            verified=True,
            is_admin=True,
        )
        cust = User.objects.create_user(
            email='sc_cust@st.knust.edu.gh',
            password='Password123!',
            role='student',
            verified=True,
        )
        v_user = User.objects.create_user(
            email='sc_vend@st.knust.edu.gh',
            password='Password123!',
            role='vendor',
            verified=True,
        )
        vendor = Vendor.objects.create(
            id='vend-sc-1',
            user=v_user,
            name='SC Kitchen',
            active=True,
            open=True,
        )

        paid_order = Order.objects.create(
            id='ord-sc-paid',
            customer=cust,
            vendor=vendor,
            vendor_name=vendor.name,
            email=cust.email,
            lines=[{'mealId': 'm-sc-1', 'name': 'Waakye', 'price': 40.0, 'qty': 1}],
            subtotal=Decimal('40.00'),
            fee=Decimal('2.00'),
            total=Decimal('42.00'),
            payment_status='paid',
            prep_stage='queued',
        )
        refund_case = SupportCase.objects.create(
            code='CASE-SC-REF1',
            user=cust,
            type='missing_item',
            order=paid_order.id,
            vendor=vendor.name,
            priority='high',
            note='Missing plantain from waakye pack',
        )

        client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(admin)}')

        # 1. Resolve with refund -> AuditEntry snapshot persisted, SupportCase deleted
        res_ref = client.post(f'/api/support/cases/{refund_case.code}/resolve/', {'action': 'refund'}, format='json')
        self.assertEqual(res_ref.status_code, 200)
        self.assertFalse(SupportCase.objects.filter(code=refund_case.code).exists())

        paid_order.refresh_from_db()
        self.assertEqual(paid_order.payment_status, 'refunded')
        self.assertIsNotNone(paid_order.cancelled_at)

        audit_ref = AuditEntry.objects.filter(entity_type='support_case', entity_id=refund_case.code).first()
        self.assertIsNotNone(audit_ref)
        self.assertEqual(audit_ref.actor, admin.email)
        self.assertEqual(audit_ref.action, 'case_refund')
        extra = audit_ref.extra or {}
        self.assertEqual(extra.get('code'), refund_case.code)
        self.assertEqual(extra.get('caseCode'), refund_case.code)
        self.assertEqual(extra.get('order'), paid_order.id)
        self.assertEqual(extra.get('orderId'), paid_order.id)
        self.assertEqual(extra.get('customer'), cust.email)
        self.assertEqual(extra.get('vendor'), vendor.name)
        self.assertEqual(extra.get('description'), refund_case.note)
        self.assertEqual(extra.get('decision'), 'refund')
        self.assertEqual(extra.get('refundAmount'), '42.00')
        self.assertEqual(extra.get('refund_amount'), '42.00')
        self.assertEqual(extra.get('actor'), admin.email)
        self.assertTrue(extra.get('timestamp'))
        datetime.fromisoformat(extra['timestamp'])

        # Double-resolve returns 404
        res_ref_again = client.post(f'/api/support/cases/{refund_case.code}/resolve/', {'action': 'refund'}, format='json')
        self.assertEqual(res_ref_again.status_code, 404)

        # 2. Dismiss a second case (with case.user=None, falling back to Order.email for customer)
        other_order = Order.objects.create(
            id='ord-sc-other',
            customer=cust,
            vendor=vendor,
            vendor_name=vendor.name,
            email=cust.email,
            lines=[{'mealId': 'm-sc-2', 'name': 'Jollof', 'price': 20.0, 'qty': 1}],
            subtotal=Decimal('20.00'),
            fee=Decimal('1.00'),
            total=Decimal('21.00'),
            payment_status='paid',
            prep_stage='queued',
        )
        dismiss_case = SupportCase.objects.create(
            code='CASE-SC-DIS1',
            user=None,
            type='late_delivery',
            order=other_order.id,
            vendor=vendor.name,
            priority='normal',
            note='Arrived 10 mins after break',
        )
        res_dis = client.post(f'/api/support/cases/{dismiss_case.code}/resolve/', {'action': 'dismiss'}, format='json')
        self.assertEqual(res_dis.status_code, 200)
        self.assertFalse(SupportCase.objects.filter(code=dismiss_case.code).exists())

        audit_dis = AuditEntry.objects.filter(entity_type='support_case', entity_id=dismiss_case.code).first()
        self.assertIsNotNone(audit_dis)
        self.assertEqual(audit_dis.action, 'case_dismiss')
        dis_extra = audit_dis.extra or {}
        self.assertEqual(dis_extra.get('decision'), 'dismiss')
        self.assertEqual(dis_extra.get('refundAmount'), '0.00')
        self.assertEqual(dis_extra.get('refund_amount'), '0.00')
        self.assertEqual(dis_extra.get('customer'), cust.email)
        self.assertEqual(dis_extra.get('description'), dismiss_case.note)
        self.assertEqual(dis_extra.get('order'), other_order.id)
        self.assertEqual(dis_extra.get('vendor'), vendor.name)

        res_dis_again = client.post(f'/api/support/cases/{dismiss_case.code}/resolve/', {'action': 'dismiss'}, format='json')
        self.assertEqual(res_dis_again.status_code, 404)

        # 3. Order already in a PayoutBatch still returns 409 and does NOT delete case
        batch = PayoutBatch.objects.create(
            id='batch-sc-1',
            amount=Decimal('40.00'),
            order_count=1,
            status='paid',
        )
        batched_order = Order.objects.create(
            id='ord-sc-batched',
            customer=cust,
            vendor=vendor,
            vendor_name=vendor.name,
            email=cust.email,
            lines=[{'mealId': 'm-sc-1', 'name': 'Waakye', 'price': 40.0, 'qty': 1}],
            subtotal=Decimal('40.00'),
            fee=Decimal('2.00'),
            total=Decimal('42.00'),
            payment_status='released',
            settlement_status='released',
            payout_batch_id=batch.id,
        )
        batched_case = SupportCase.objects.create(
            code='CASE-SC-BAT1',
            user=cust,
            type='quality',
            order=batched_order.id,
            vendor=vendor.name,
            priority='normal',
            note='Portion felt small',
        )
        res_bat = client.post(f'/api/support/cases/{batched_case.code}/resolve/', {'action': 'refund'}, format='json')
        self.assertEqual(res_bat.status_code, 409)
        self.assertTrue(SupportCase.objects.filter(code=batched_case.code).exists())


class JwtIssuerAndDecimalSubtotalTests(_DjangoTestCase):
    """WP7: Enforce JWT iss='stew' + 12h default lifetime, and direct Decimal subtotal accumulation."""

    def test_jwt_requires_iss_stew_and_defaults_to_12h_lifetime(self):
        from datetime import datetime, timezone
        import jwt
        from django.conf import settings
        from django.test import override_settings
        from api.models import User
        from api.security import decode_jwt_token, generate_jwt_token, password_fingerprint

        self.assertEqual(settings.JWT_ACCESS_TOKEN_LIFETIME_HOURS, 12)

        user = User.objects.create_user(
            email='wp7_jwt@st.knust.edu.gh',
            password='Password123!',
            role='student',
            verified=True,
        )

        # Default token carries iss='stew' and 12h lifetime
        tok = generate_jwt_token(user)
        decoded = decode_jwt_token(tok)
        self.assertEqual(decoded.get('iss'), 'stew')
        self.assertEqual(decoded['exp'] - decoded['iat'], 12 * 3600)

        # Setting override still honored dynamically
        with override_settings(JWT_ACCESS_TOKEN_LIFETIME_HOURS=4):
            tok4 = generate_jwt_token(user)
            dec4 = decode_jwt_token(tok4)
            self.assertEqual(dec4.get('iss'), 'stew')
            self.assertEqual(dec4['exp'] - dec4['iat'], 4 * 3600)

        # Tokens without iss or with wrong iss are rejected with 401
        now = int(datetime.now(timezone.utc).timestamp())
        base_payload = {
            'sub': str(user.id),
            'jti': 'wp7testjti0001',
            'role': user.role,
            'pv': password_fingerprint(user),
            'iat': now,
            'exp': now + 3600,
        }
        tok_no_iss = jwt.encode(base_payload, settings.SECRET_KEY, algorithm='HS256')
        tok_wrong_iss = jwt.encode({**base_payload, 'iss': 'other-app'}, settings.SECRET_KEY, algorithm='HS256')

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {tok_no_iss}')
        res_no = client.get('/api/auth/me/')
        self.assertEqual(res_no.status_code, 401)

        client.credentials(HTTP_AUTHORIZATION=f'Bearer {tok_wrong_iss}')
        res_wrong = client.get('/api/auth/me/')
        self.assertEqual(res_wrong.status_code, 401)

        client.credentials(HTTP_AUTHORIZATION=f'Bearer {tok}')
        res_ok = client.get('/api/auth/me/')
        self.assertEqual(res_ok.status_code, 200)

    def test_order_creation_uses_exact_decimal_subtotal_and_preserves_numeric_line_price(self):
        from decimal import Decimal
        from api.models import Meal, Order, User, Vendor
        from api.security import generate_jwt_token

        cust = User.objects.create_user(
            email='wp7_cust@st.knust.edu.gh',
            password='Password123!',
            role='student',
            verified=True,
        )
        v_user = User.objects.create_user(
            email='wp7_vend@st.knust.edu.gh',
            password='Password123!',
            role='vendor',
            verified=True,
        )
        vendor = Vendor.objects.create(
            id='vend-wp7-1',
            user=v_user,
            name='WP7 Kitchen',
            active=True,
            open=True,
        )
        meal = Meal.objects.create(
            id='meal-wp7-1',
            vendor=vendor,
            name='Special Fried Rice',
            price=Decimal('7.77'),
            left=20,
            on=True,
        )

        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(cust)}')
        res = client.post(
            '/api/orders/',
            {
                'lines': [{'mealId': meal.id, 'qty': 3}],
                'location': 'Republic Hall',
                'phone': '0240000001',
            },
            format='json',
        )
        self.assertEqual(res.status_code, 201, res.data)

        order = Order.objects.get(id=res.data['id'])
        self.assertEqual(order.subtotal, Decimal('23.31'))
        self.assertEqual(order.fee, Decimal('1.17'))
        self.assertEqual(order.total, Decimal('24.48'))
        self.assertEqual(res.data['lines'][0]['price'], 7.77)
        self.assertIsInstance(res.data['lines'][0]['price'], float)


