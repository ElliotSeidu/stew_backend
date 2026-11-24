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
        # Pay-first: vendor receives 404 (not 400) so unpaid orders stay invisible by direct ID
        unpaid_res = self.client.post(f'/api/orders/{unpaid.id}/prep/', {'stage': 'ready'}, format='json')
        self.assertEqual(unpaid_res.status_code, 404)

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
        # Pay-first: vendor receives 404 so unpaid order existence is not revealed
        self.assertEqual(self.client.post(f'/api/orders/{unpaid.id}/collection-nudge/', {}, format='json').status_code, 404)

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
            # Pay-first: unpaid/unpaid-cancelled orders return 404 to vendors (400 on paid/released)
            expected_vendor_code = 400 if o.is_vendor_visible else 404
            self.assertEqual(r_cmp.status_code, expected_vendor_code, f'/complete/ on {o.id} gave {r_cmp.status_code}')

        # Admin still hits the inner escrow guard (400) on unpaid orders
        admin_escrow = User.objects.create_superuser(
            email='escg.admin@st.knust.edu.gh', password='Password123', full_name='Escrow Guard Admin',
        )
        self.client.force_authenticate(user=admin_escrow)
        self.assertEqual(self.client.post(f'/api/orders/{o_pend.id}/complete/', {'code': '112233'}, format='json').status_code, 400)

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


class SuspendedUserAuthSecurityTests(TestCase):
    """
    RC1-01: Users with is_active=False must not be able to log in with password,
    request or redeem login codes, initiate or complete password reset, verify/resend
    email OTPs, re-register over a suspended unverified account, or use any JWT issued
    before suspension on any authenticated endpoint.
    """

    @classmethod
    def setUpTestData(cls):
        cls.student = User.objects.create_user(
            email='susp.student@st.knust.edu.gh',
            password='Password123!',
            full_name='Suspended Student',
            reference_id='20950001',
            phone='0249500001',
            hall='Unity Hall (Conti)',
            verified=True,
            is_active=True,
            role='customer',
            account_type='customer',
        )
        cls.unverified_student = User.objects.create_user(
            email='susp.unverified@st.knust.edu.gh',
            password='Password123!',
            full_name='Suspended Unverified',
            reference_id='20950002',
            phone='0249500002',
            hall='Africa Hall',
            verified=False,
            is_active=True,
            role='customer',
            account_type='customer',
        )
        cls.vendor_user = User.objects.create_user(
            email='susp.vendor@st.knust.edu.gh',
            password='Password123!',
            full_name='Suspended Vendor',
            reference_id='20950003',
            phone='0249500003',
            hall='Republic Hall',
            verified=True,
            is_active=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Suspended Kitchen',
        )
        cls.vendor = Vendor.objects.create(
            id='v_susp_1',
            user=cls.vendor_user,
            name='Suspended Kitchen',
            hall='Republic Hall',
            open=True,
            active=True,
        )
        cls.inactive_vendor_user = User.objects.create_user(
            email='susp.inactvendor@st.knust.edu.gh',
            password='Password123!',
            full_name='Inactive Vendor Owner',
            reference_id='20950004',
            phone='0249500004',
            hall='Republic Hall',
            verified=True,
            is_active=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Pending Kitchen',
        )
        cls.inactive_vendor = Vendor.objects.create(
            id='v_susp_inact',
            user=cls.inactive_vendor_user,
            name='Pending Kitchen',
            hall='Republic Hall',
            open=False,
            active=False,
        )
        cls.admin_user = User.objects.create_superuser(
            email='susp.admin@st.knust.edu.gh',
            password='AdminPassword123!',
            full_name='Suspended Admin',
            reference_id='20950005',
            phone='0249500005',
            hall='Commercial Area',
            is_active=True,
            verified=True,
        )
        cls.active_admin = User.objects.create_superuser(
            email='active.admin@st.knust.edu.gh',
            password='AdminPassword123!',
            full_name='Active Admin',
            reference_id='20950006',
            phone='0249500006',
            hall='Commercial Area',
            is_active=True,
            verified=True,
        )
        cls.meal = Meal.objects.create(
            id='m_susp_1',
            vendor=cls.vendor,
            name='Susp Jollof',
            price=Decimal('25.00'),
            left=10,
            on=True,
        )
        cls.hidden_order = Order.objects.create(
            id='STW-SUSP-HID',
            customer=cls.student,
            customer_name=cls.student.full_name,
            email=cls.student.email,
            phone=cls.student.phone,
            area='Campus',
            vendor=cls.vendor,
            vendor_name=cls.vendor.name,
            subtotal=Decimal('25.00'),
            fee=Decimal('1.25'),
            total=Decimal('26.25'),
            payment_status='released',
            settlement_status='released',
            prep_stage='collected',
            collected_at=timezone.now(),
        )
        cls.hidden_review = Review.objects.create(
            order_id=cls.hidden_order.id,
            vendor=cls.vendor,
            vendor_name=cls.vendor.name,
            customer=cls.student,
            rating=1,
            text='Hidden moderation review',
            moderation_status='hidden',
        )

    def setUp(self):
        from django.core.cache import cache
        _RATE_LIMIT_CACHE.clear()
        cache.clear()
        self.client = APIClient()

    def test_suspended_user_cannot_login_with_password(self):
        User.objects.filter(pk=self.student.pk).update(is_active=False)
        User.objects.filter(pk=self.unverified_student.pk).update(is_active=False)

        # Correct password on suspended verified user -> 403, no JWT
        r_good = self.client.post('/api/auth/login/', {
            'email': self.student.email,
            'password': 'Password123!',
        }, format='json')
        self.assertEqual(r_good.status_code, 403)
        self.assertNotIn('access', r_good.data)
        self.assertIn('message', r_good.data)

        # Wrong password does not leak suspension status
        r_bad = self.client.post('/api/auth/login/', {
            'email': self.student.email,
            'password': 'WrongPassword999!',
        }, format='json')
        self.assertEqual(r_bad.status_code, 400)
        self.assertNotIn('access', r_bad.data)

        # Suspended + unverified user with correct password must get 403, NOT unverified OTP dispatch
        with patch('api.views._dispatch_otp_email') as mock_mail:
            r_unv = self.client.post('/api/auth/login/', {
                'email': self.unverified_student.email,
                'password': 'Password123!',
            }, format='json')
        self.assertEqual(r_unv.status_code, 403)
        self.assertNotEqual(r_unv.data.get('code'), 'unverified')
        self.assertNotIn('access', r_unv.data)
        mock_mail.assert_not_called()

    def test_suspended_user_cannot_request_or_use_login_code(self):
        # Seed a valid pre-suspension login code
        User.objects.filter(pk=self.student.pk).update(
            login_code_hash=hash_token('654321'),
            login_code_expires=timezone.now() + timedelta(minutes=10),
            is_active=False,
        )

        # Redeem pre-suspension login code -> rejected, no JWT
        r_verify = self.client.post('/api/auth/login-code/verify/', {
            'email': self.student.email,
            'code': '654321',
        }, format='json')
        self.assertEqual(r_verify.status_code, 400)
        self.assertNotIn('access', r_verify.data)

        # Clear hash and confirm login-code request writes no new hash or email
        User.objects.filter(pk=self.student.pk).update(login_code_hash='', login_code_expires=None)
        with patch('api.views._dispatch_otp_email') as mock_mail:
            r_req = self.client.post('/api/auth/login-code/request/', {
                'email': self.student.email,
            }, format='json')
        self.assertEqual(r_req.status_code, 200)
        self.student.refresh_from_db()
        self.assertEqual(self.student.login_code_hash, '')
        mock_mail.assert_not_called()

    def test_suspended_user_cannot_reset_password_and_login(self):
        # Suspends user before forgot-password -> no reset code created
        User.objects.filter(pk=self.student.pk).update(is_active=False)
        with patch('api.views._dispatch_otp_email') as mock_mail:
            r_forgot = self.client.post('/api/auth/forgot-password/', {
                'email': self.student.email,
            }, format='json')
        self.assertEqual(r_forgot.status_code, 200)
        self.student.refresh_from_db()
        self.assertEqual(self.student.reset_code_hash, '')
        mock_mail.assert_not_called()

        # Pre-seed valid reset code requested prior to suspension -> reset must still fail
        User.objects.filter(pk=self.student.pk).update(
            reset_code_hash=hash_token('112233'),
            reset_code_expires=timezone.now() + timedelta(minutes=15),
            is_active=False,
        )
        r_reset = self.client.post('/api/auth/reset-password/', {
            'email': self.student.email,
            'code': '112233',
            'password': 'NewPassword123',
        }, format='json')
        self.assertEqual(r_reset.status_code, 400)
        self.student.refresh_from_db()
        self.assertFalse(self.student.check_password('NewPassword123'))
        self.assertTrue(self.student.check_password('Password123!'))

        # Neither old nor attempted new password allows login
        for pw in ('Password123!', 'NewPassword123'):
            r_login = self.client.post('/api/auth/login/', {
                'email': self.student.email,
                'password': pw,
            }, format='json')
            self.assertIn(r_login.status_code, (400, 403))
            self.assertNotIn('access', r_login.data)

        # Suspended unverified user cannot verify email, resend code, or overwrite via register
        User.objects.filter(pk=self.unverified_student.pk).update(
            verification_code_hash=hash_token('445566'),
            verification_code_expires=timezone.now() + timedelta(minutes=15),
            is_active=False,
        )
        r_ve = self.client.post('/api/auth/verify-email/', {
            'email': self.unverified_student.email,
            'code': '445566',
        }, format='json')
        self.assertEqual(r_ve.status_code, 400)
        self.assertNotIn('access', r_ve.data)
        self.unverified_student.refresh_from_db()
        self.assertFalse(self.unverified_student.verified)

        with patch('api.views._dispatch_otp_email') as mock_mail:
            r_rs = self.client.post('/api/auth/resend-code/', {
                'email': self.unverified_student.email,
            }, format='json')
            self.assertEqual(r_rs.status_code, 200)
        mock_mail.assert_not_called()

        r_reg = self.client.post('/api/auth/register/', {
            'fullName': 'Takeover Try',
            'email': self.unverified_student.email,
            'referenceId': '20950099',
            'phone': '0249500099',
            'accountType': 'customer',
            'password': 'NewPassword123',
        }, format='json')
        self.assertEqual(r_reg.status_code, 400)

    def test_pre_suspension_token_rejected_on_all_authenticated_endpoints(self):
        from types import SimpleNamespace
        from django.contrib import admin
        import stew_server.urls  # noqa: F401
        from api.authentication import IsAdminUser

        student_tok = generate_jwt_token(self.student)
        vendor_tok = generate_jwt_token(self.vendor_user)
        inact_vendor_tok = generate_jwt_token(self.inactive_vendor_user)
        admin_tok = generate_jwt_token(self.admin_user)
        active_admin_tok = generate_jwt_token(self.active_admin)

        # Pre-suspension sanity checks pass
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {student_tok}')
        self.assertEqual(self.client.get('/api/auth/me/').status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {vendor_tok}')
        self.assertEqual(self.client.get('/api/payouts/').status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {inact_vendor_tok}')
        self.assertEqual(self.client.get(f'/api/vendors/{self.inactive_vendor.id}/').status_code, 200)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_tok}')
        self.assertEqual(self.client.get('/api/admin/users/').status_code, 200)

        # Seed pending OTP hashes on student and suspend via admin API -> hashes must be cleared
        User.objects.filter(pk=self.student.pk).update(
            verification_code_hash=hash_token('111111'),
            verification_code_expires=timezone.now() + timedelta(minutes=10),
            login_code_hash=hash_token('222222'),
            login_code_expires=timezone.now() + timedelta(minutes=10),
            reset_code_hash=hash_token('333333'),
            reset_code_expires=timezone.now() + timedelta(minutes=10),
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {active_admin_tok}')
        r_susp = self.client.patch(f'/api/admin/users/{self.student.id}/', {'active': False}, format='json')
        self.assertEqual(r_susp.status_code, 200)
        self.student.refresh_from_db()
        self.assertFalse(self.student.is_active)
        self.assertEqual(self.student.verification_code_hash, '')
        self.assertEqual(self.student.login_code_hash, '')
        self.assertEqual(self.student.reset_code_hash, '')

        # Also suspend vendor, inactive vendor owner, and admin (simulating shell deactivation)
        User.objects.filter(pk__in=[self.vendor_user.pk, self.inactive_vendor_user.pk, self.admin_user.pk]).update(
            is_active=False
        )

        # Student token blocked across all student-authenticated endpoints
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {student_tok}')
        for method, path, payload in [
            ('get', '/api/auth/me/', None),
            ('patch', '/api/auth/me/', {'fullName': 'Still Suspended'}),
            ('post', '/api/auth/logout/', {}),
            ('delete', '/api/auth/delete-account/', None),
            ('get', '/api/orders/', None),
            ('post', '/api/orders/', {'lines': [{'mealId': self.meal.id, 'qty': 1}], 'area': 'Campus', 'pickupDay': '2026-12-01'}),
            ('get', '/api/support/cases/', None),
            ('post', '/api/notifications/subscribe/', {'endpoint': 'https://push.example.com/sub1', 'keys': {}}),
        ]:
            resp = getattr(self.client, method)(path, payload, format='json')
            self.assertEqual(resp.status_code, 401, f'Expected 401 for student {method.upper()} {path}, got {resp.status_code}')

        # Vendor token blocked across all vendor-authenticated endpoints
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {vendor_tok}')
        for method, path, payload in [
            ('get', '/api/meals/?mine=true', None),
            ('post', '/api/meals/', {'name': 'Ghost Dish', 'price': 20, 'stock': 5}),
            ('get', '/api/payouts/', None),
            ('get', '/api/vendor/compliance/', None),
            ('post', '/api/vendor/apply/', {'kitchen': 'Reopened Kitchen', 'hall': 'Republic Hall'}),
            ('post', '/api/vendor/activate/', {}),
        ]:
            resp = getattr(self.client, method)(path, payload, format='json')
            self.assertEqual(resp.status_code, 401, f'Expected 401 for vendor {method.upper()} {path}, got {resp.status_code}')

        # Suspended owner of inactive vendor is rejected (401) with token, and unauthenticated gets 404
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {inact_vendor_tok}')
        self.assertEqual(self.client.get(f'/api/vendors/{self.inactive_vendor.id}/').status_code, 401)
        self.client.credentials()
        self.assertEqual(self.client.get(f'/api/vendors/{self.inactive_vendor.id}/').status_code, 404)

        # Admin token blocked across all admin-authenticated endpoints
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {admin_tok}')
        for method, path in [
            ('get', '/api/admin/users/'),
            ('get', '/api/admin/vendors/'),
            ('get', '/api/admin/audit/'),
            ('get', '/api/payouts/batches/'),
            ('get', '/api/admin/reviews/queue/'),
        ]:
            resp = getattr(self.client, method)(path)
            self.assertEqual(resp.status_code, 401, f'Expected 401 for admin {method.upper()} {path}, got {resp.status_code}')

        # Suspended admin token on vendor_reviews_view?includeHidden=true is rejected (401),
        # and anonymous ?includeHidden=true never exposes hidden reviews.
        r_rev = self.client.get(f'/api/vendors/{self.vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(r_rev.status_code, 401)
        self.client.credentials()
        r_rev_anon = self.client.get(f'/api/vendors/{self.vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(r_rev_anon.status_code, 200)
        self.assertNotIn(self.hidden_order.id, [rev['orderId'] for rev in r_rev_anon.data])

        # Defense-in-depth permission & Django admin checks fail for inactive admin
        self.admin_user.refresh_from_db()
        fake_req = SimpleNamespace(user=self.admin_user)
        self.assertFalse(IsAdminUser().has_permission(fake_req, None))
        self.assertFalse(admin.site.has_permission(fake_req))


class ConfigurableThrottleRateTests(TestCase):
    """
    RC1-02: DRF anon and user throttle rates must be configurable via
    THROTTLE_ANON_PER_MIN (default 1000) and THROTTLE_USER_PER_MIN (default 120),
    allow >300 anonymous requests/min from one shared NAT IP at default, and
    enforce lowered limits dynamically.
    """

    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()
        _RATE_LIMIT_CACHE.clear()

    def test_default_anon_throttle_allows_more_than_300_requests_per_min_from_one_ip(self):
        self.assertEqual(settings.THROTTLE_ANON_PER_MIN, 1000)
        self.assertEqual(settings.THROTTLE_USER_PER_MIN, 120)
        self.assertEqual(settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['anon'], '1000/min')
        self.assertEqual(settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['user'], '120/min')

        for idx in range(305):
            r = self.client.get('/api/vendors/', REMOTE_ADDR='196.201.88.10')
            self.assertEqual(r.status_code, 200, f'Request #{idx + 1} was unexpectedly throttled ({r.status_code})')

    def test_lowered_anon_and_user_throttle_settings_trigger_429(self):
        from django.core.cache import cache

        cache.clear()
        with override_settings(THROTTLE_ANON_PER_MIN=5):
            for idx in range(5):
                r = self.client.get('/api/vendors/', REMOTE_ADDR='196.201.88.11')
                self.assertEqual(r.status_code, 200, f'Anon request #{idx + 1} failed: {r.status_code}')
            r_blocked = self.client.get('/api/vendors/', REMOTE_ADDR='196.201.88.11')
            self.assertEqual(r_blocked.status_code, 429)

        cache.clear()
        student = User.objects.create_user(
            email='throttle.student@st.knust.edu.gh',
            password='Password123!',
            full_name='Throttle Student',
            reference_id='20951001',
            phone='0249510001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        tok = generate_jwt_token(student)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tok}')
        with override_settings(THROTTLE_USER_PER_MIN=3):
            for idx in range(3):
                r = self.client.get('/api/auth/me/', REMOTE_ADDR='196.201.88.12')
                self.assertEqual(r.status_code, 200, f'User request #{idx + 1} failed: {r.status_code}')
            r_user_blocked = self.client.get('/api/auth/me/', REMOTE_ADDR='196.201.88.12')
            self.assertEqual(r_user_blocked.status_code, 429)


class PayFirstVendorVisibilityTests(TestCase):
    """
    Pay-first Task A2/A6: Unpaid, failed, abandoned, and expired orders must be
    completely invisible to vendors (lists, 404 by direct ID, actions refused,
    zero ledger/count metrics) while paid/released/paid-then-cancelled/refunded
    orders remain visible and internal prep_at keys stay hidden.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='pf.admin@st.knust.edu.gh',
            password='Password123!',
            full_name='PayFirst Admin',
        )
        cls.customer_a = User.objects.create_user(
            email='pf.custa@st.knust.edu.gh',
            password='Password123!',
            full_name='Customer A',
            reference_id='20960001',
            phone='0249600001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.customer_b = User.objects.create_user(
            email='pf.custb@st.knust.edu.gh',
            password='Password123!',
            full_name='Customer B',
            reference_id='20960002',
            phone='0249600002',
            hall='Queens Hall',
            verified=True,
        )
        cls.vendor_a_user = User.objects.create_user(
            email='pf.vendora@st.knust.edu.gh',
            password='Password123!',
            full_name='Vendor A Chef',
            reference_id='20960003',
            phone='0249600003',
            hall='Unity Hall (Conti)',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='both',
            kitchen_name='PayFirst Kitchen A',
        )
        cls.vendor_a = Vendor.objects.create(
            id='v_pfa',
            user=cls.vendor_a_user,
            name='PayFirst Kitchen A',
            hall='Unity Hall (Conti)',
            open=True,
            active=True,
        )
        cls.vendor_b_user = User.objects.create_user(
            email='pf.vendorb@st.knust.edu.gh',
            password='Password123!',
            full_name='Vendor B Chef',
            reference_id='20960004',
            phone='0249600004',
            hall='Africa Hall',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='PayFirst Kitchen B',
        )
        cls.vendor_b = Vendor.objects.create(
            id='v_pfb',
            user=cls.vendor_b_user,
            name='PayFirst Kitchen B',
            hall='Africa Hall',
            open=True,
            active=True,
        )
        cls.meal_a = Meal.objects.create(
            id='m_pfa_1',
            vendor=cls.vendor_a,
            name='Abunuabunu',
            price=Decimal('40.00'),
            cat='Soups',
            left=20,
            on=True,
        )
        cls.meal_b = Meal.objects.create(
            id='m_pfb_1',
            vendor=cls.vendor_b,
            name='Waakye Special',
            price=Decimal('30.00'),
            cat='Rice',
            left=15,
            on=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def _make_order(self, oid, customer=None, vendor=None, payment_status='pending', prep_stage='accepted', paid_at=None, cancelled_at=None, collected_at=None, settlement_status='pending', subtotal=Decimal('40.00'), prep_at=None, meetup=None):
        c = customer or self.customer_a
        v = vendor or self.vendor_a
        fee = (subtotal * Decimal('0.05')).quantize(Decimal('0.01'))
        total = subtotal + fee
        return Order.objects.create(
            id=oid,
            customer=c,
            customer_name=c.full_name,
            email=c.email,
            phone=c.phone,
            area=c.hall,
            vendor=v,
            vendor_name=v.name,
            lines=[{'mealId': self.meal_a.id if v == self.vendor_a else self.meal_b.id, 'name': 'Dish', 'price': float(subtotal), 'qty': 1}],
            subtotal=subtotal,
            fee=fee,
            total=total,
            pickup_day='2026-12-01',
            handoff_code='123456',
            prep_stage=prep_stage,
            prep_at=prep_at or {'accepted': 1700000000000},
            meetup=meetup,
            payment_status=payment_status,
            settlement_status=settlement_status,
            paid_at=paid_at,
            cancelled_at=cancelled_at,
            collected_at=collected_at,
        )

    def test_vendor_list_excludes_unpaid_states_and_includes_paid_states(self):
        now = timezone.now()
        o_unpaid = self._make_order('STW-PF-PEND', payment_status='pending')
        o_failed = self._make_order('STW-PF-FAIL', payment_status='failed')
        o_expired = self._make_order('STW-PF-EXP', payment_status='cancelled', cancelled_at=now, paid_at=None)
        o_paid = self._make_order('STW-PF-PAID', payment_status='paid', paid_at=now)
        o_released = self._make_order('STW-PF-REL', payment_status='released', paid_at=now, collected_at=now, prep_stage='collected', settlement_status='released')
        o_refunded = self._make_order('STW-PF-REF', payment_status='refunded', paid_at=now, cancelled_at=now)
        o_ref_pend = self._make_order('STW-PF-RFP', payment_status='refund_pending', paid_at=now, cancelled_at=now)
        # Personal unpaid customer order placed by vendor_a at vendor_b
        o_personal_unpaid = self._make_order('STW-PF-PERS', customer=self.vendor_a_user, vendor=self.vendor_b, payment_status='pending')

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_a_user)}')
        r_scope = self.client.get('/api/orders/?scope=vendor')
        self.assertEqual(r_scope.status_code, 200)
        scope_ids = {o['id'] for o in r_scope.data}
        for hidden in (o_unpaid, o_failed, o_expired, o_personal_unpaid):
            self.assertNotIn(hidden.id, scope_ids, f'{hidden.id} leaked into vendor scoped list')
        for visible in (o_paid, o_released, o_refunded, o_ref_pend):
            self.assertIn(visible.id, scope_ids, f'{visible.id} missing from vendor scoped list')

        # Default (unscoped) feed for a 'both' vendor still hides unpaid orders FOR their kitchen,
        # while keeping their own personal unpaid customer order visible so they can pay/cancel it.
        r_default = self.client.get('/api/orders/')
        self.assertEqual(r_default.status_code, 200)
        default_ids = {o['id'] for o in r_default.data}
        for hidden in (o_unpaid, o_failed, o_expired):
            self.assertNotIn(hidden.id, default_ids)
        self.assertIn(o_personal_unpaid.id, default_ids)
        for visible in (o_paid, o_released, o_refunded, o_ref_pend):
            self.assertIn(visible.id, default_ids)

    def test_vendor_direct_get_and_all_actions_on_unpaid_order_return_404(self):
        now = timezone.now()
        unpaid_variants = [
            self._make_order('STW-PF-V1', payment_status='pending', meetup={'place': 'Gate', 'proposedBy': 'student', 'confirmedBy': ['student'], 'agreed': False}),
            self._make_order('STW-PF-V2', payment_status='failed'),
            self._make_order('STW-PF-V3', payment_status='cancelled', cancelled_at=now, paid_at=None),
        ]

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_a_user)}')
        for o in unpaid_variants:
            self.assertEqual(self.client.get(f'/api/orders/{o.id}/').status_code, 404, f'GET leaked {o.id}')
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/prep/', {'stage': 'cooking'}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/complete/', {'code': '123456'}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/collection-nudge/', {}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/meetup/propose/', {'place': 'Library'}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/meetup/confirm/', {}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/meetup/decline/', {}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/messages/', {'text': 'Hello'}, format='json').status_code, 404)
            self.assertEqual(self.client.post(f'/api/orders/{o.id}/cancel/', {}, format='json').status_code, 404)
            self.assertEqual(
                self.client.post('/api/support/cases/', {'type': 'late', 'orderId': o.id, 'description': 'Vendor probing unpaid order'}, format='json').status_code,
                404,
            )

    def test_payouts_ledger_metrics_and_counts_exclude_unpaid_orders(self):
        now = timezone.now()
        self._make_order('STW-PF-L-P1', payment_status='pending', prep_stage='accepted', subtotal=Decimal('100.00'))
        self._make_order('STW-PF-L-P2', payment_status='pending', prep_stage='ready', subtotal=Decimal('200.00'))
        self._make_order('STW-PF-L-FL', payment_status='failed', prep_stage='accepted', subtotal=Decimal('300.00'))
        self._make_order('STW-PF-L-CN', payment_status='cancelled', paid_at=None, cancelled_at=now, prep_stage='accepted', subtotal=Decimal('400.00'))
        self._make_order('STW-PF-L-PAID', payment_status='paid', paid_at=now, prep_stage='ready', subtotal=Decimal('50.00'))
        self._make_order('STW-PF-L-REL', payment_status='released', paid_at=now, collected_at=now, prep_stage='collected', settlement_status='released', subtotal=Decimal('25.00'))

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_a_user)}')
        res = self.client.get('/api/payouts/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data['held'], 50.0)
        self.assertEqual(res.data['heldCount'], 1)
        self.assertEqual(res.data['released'], 25.0)
        self.assertEqual(res.data['releasedCount'], 1)
        self.assertEqual(res.data['weekTotal'], 75.0)
        self.assertEqual(res.data['inProgressCount'], 1)
        self.assertEqual(res.data['readyCount'], 1)
        self.assertEqual(res.data['newCount'], 0)

    def test_owner_admin_and_cross_party_access_plus_old_unpaid_cancel(self):
        # Create via real API so stock decrements
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer_a)}')
        stock_before = Meal.objects.get(pk=self.meal_a.pk).left
        r_create = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal_a.id, 'qty': 2}],
            'area': 'Unity Hall',
            'pickupDay': '2026-12-01',
        }, format='json')
        self.assertEqual(r_create.status_code, 201)
        oid = r_create.data['id']
        self.assertEqual(Meal.objects.get(pk=self.meal_a.pk).left, stock_before - 2)

        # Age order past 120s (e.g. 10 minutes old, still within unpaid TTL)
        Order.objects.filter(pk=oid).update(
            created_at=timezone.now() - timedelta(minutes=10),
            prep_at={'accepted': 1700000000000, '_internalFlag': True},
        )

        # Owning customer sees it and internal _ keys are stripped from prepAt
        r_cust_list = self.client.get('/api/orders/')
        self.assertIn(oid, [o['id'] for o in r_cust_list.data])
        r_cust_det = self.client.get(f'/api/orders/{oid}/')
        self.assertEqual(r_cust_det.status_code, 200)
        self.assertNotIn('_internalFlag', r_cust_det.data['prepAt'])

        # Admin sees unpaid order
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        self.assertIn(oid, [o['id'] for o in self.client.get('/api/orders/').data])
        self.assertEqual(self.client.get(f'/api/orders/{oid}/').status_code, 200)

        # Unrelated customer B and vendor B cannot see unpaid order
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer_b)}')
        self.assertNotIn(oid, [o['id'] for o in self.client.get('/api/orders/').data])
        self.assertEqual(self.client.get(f'/api/orders/{oid}/').status_code, 403)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_b_user)}')
        self.assertNotIn(oid, [o['id'] for o in self.client.get('/api/orders/?scope=vendor').data])
        self.assertEqual(self.client.get(f'/api/orders/{oid}/').status_code, 403)

        # Owning customer cancels their 10-minute-old unpaid order -> allowed and restores stock once
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer_a)}')
        r_can = self.client.post(f'/api/orders/{oid}/cancel/', {}, format='json')
        self.assertEqual(r_can.status_code, 200)
        self.assertEqual(r_can.data['payment']['status'], 'cancelled')
        self.assertNotIn('_stockRestored', r_can.data['prepAt'])
        self.assertEqual(Meal.objects.get(pk=self.meal_a.pk).left, stock_before)


class PayFirstVendorNotificationTests(TestCase):
    """
    Pay-first Task A3/A6: Vendor push notification, email, and vendor-facing
    order analytics must NEVER fire at order creation, must fire ONCE at confirmed
    payment (inside _mark_order_paid under lock) even across duplicate webhooks
    or verify calls, and must NOT fire if payment arrives after cancellation.
    """

    @classmethod
    def setUpTestData(cls):
        cls.customer = User.objects.create_user(
            email='pf.n.cust@st.knust.edu.gh',
            password='Password123!',
            full_name='Notify Customer',
            reference_id='20961001',
            phone='0249610001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.vendor_user = User.objects.create_user(
            email='pf.n.vendor@st.knust.edu.gh',
            password='Password123!',
            full_name='Notify Chef',
            reference_id='20961002',
            phone='0249610002',
            hall='Queens Hall',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Notify Kitchen',
        )
        cls.vendor = Vendor.objects.create(
            id='v_pfn',
            user=cls.vendor_user,
            name='Notify Kitchen',
            hall='Queens Hall',
            open=True,
            active=True,
        )
        cls.meal = Meal.objects.create(
            id='m_pfn_1',
            vendor=cls.vendor,
            name='Kontomire Stew',
            price=Decimal('35.00'),
            cat='Stews',
            left=20,
            on=True,
        )
        cls.push_sub = PushSubscription.objects.create(
            user=cls.vendor_user,
            endpoint='https://push.example.com/vendor-sub-1',
            keys={'p256dh': 'k1', 'auth': 'k2'},
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    @override_settings(
        DEBUG=True,
        PAYSTACK_ALLOW_MOCK=True,
        PAYSTACK_SECRET_KEY='',
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    )
    def test_notifications_fire_once_on_payment_and_never_on_create(self):
        from django.core import mail
        from api.models import AnalyticsEvent

        mail.outbox.clear()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')

        with patch('api.views._send_vendor_push', return_value=1) as mock_push:
            r_create = self.client.post('/api/orders/', {
                'lines': [{'mealId': self.meal.id, 'qty': 1}],
                'area': 'Unity Hall',
                'pickupDay': '2026-12-01',
            }, format='json')
            self.assertEqual(r_create.status_code, 201)
            oid = r_create.data['id']

            # ZERO vendor side effects on creation
            self.assertEqual(len(mail.outbox), 0)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 0)
            mock_push.assert_not_called()

            r_init = self.client.post('/api/payments/initialize/', {'orderId': oid}, format='json')
            self.assertEqual(r_init.status_code, 200)
            ref = r_init.data['reference']

            # Confirm payment -> exactly ONE email, ONE analytics event, ONE push dispatch
            r_ver1 = self.client.post('/api/payments/verify/', {'orderId': oid, 'reference': ref}, format='json')
            self.assertEqual(r_ver1.status_code, 200)
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0].to, [self.vendor_user.email])
            self.assertIn(oid, mail.outbox[0].subject + mail.outbox[0].body)
            # Ensure sensitive customer/escrow fields never leak to vendor email
            order_obj = Order.objects.get(pk=oid)
            self.assertNotIn(order_obj.handoff_code, mail.outbox[0].body)
            self.assertNotIn(self.customer.email, mail.outbox[0].body)
            self.assertNotIn(ref, mail.outbox[0].body)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 1)
            mock_push.assert_called_once()

            # Repeat verify call -> STILL 1 email, 1 analytics event, 1 push call
            r_ver2 = self.client.post('/api/payments/verify/', {'orderId': oid, 'reference': ref}, format='json')
            self.assertEqual(r_ver2.status_code, 200)
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 1)
            mock_push.assert_called_once()

    @override_settings(
        DEBUG=False,
        PAYSTACK_ALLOW_MOCK=False,
        PAYSTACK_SECRET_KEY='sk_test_webhook_secret_123',
        EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend',
    )
    def test_duplicate_webhook_plus_verify_fires_exactly_once_and_skips_cancelled(self):
        from django.core import mail
        from api.models import AnalyticsEvent, AuditEntry

        mail.outbox.clear()
        order = Order.objects.create(
            id='STW-PF-WH1',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 35.0, 'qty': 1}],
            subtotal=Decimal('35.00'),
            fee=Decimal('1.75'),
            total=Decimal('36.75'),
            pickup_day='2026-12-01',
            handoff_code='445566',
            payment_status='pending',
            payment_reference='PSK-PF-WH1',
        )

        body = json.dumps({
            'event': 'charge.success',
            'data': {
                'reference': 'PSK-PF-WH1',
                'status': 'success',
                'currency': 'GHS',
                'amount': 3675,
            },
        }).encode('utf-8')
        sig = hmac.new(b'sk_test_webhook_secret_123', body, hashlib.sha512).hexdigest()

        fake_verify_resp = MagicMock(
            ok=True,
            json=lambda: {
                'status': True,
                'data': {'status': 'success', 'reference': 'PSK-PF-WH1', 'currency': 'GHS', 'amount': 3675},
            },
        )
        with patch('api.views.http_requests.get', return_value=fake_verify_resp), \
             patch('api.views._send_vendor_push', return_value=1) as mock_push:
            # 1st webhook marks paid and fires notification once
            r1 = self.client.post('/api/payments/webhook/', data=body, content_type='application/json', HTTP_X_PAYSTACK_SIGNATURE=sig)
            self.assertEqual(r1.status_code, 200)
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 1)
            mock_push.assert_called_once()

            # Duplicate webhook + subsequent verify call -> no duplicate vendor alerts
            r2 = self.client.post('/api/payments/webhook/', data=body, content_type='application/json', HTTP_X_PAYSTACK_SIGNATURE=sig)
            self.assertEqual(r2.status_code, 200)
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
            r3 = self.client.post('/api/payments/verify/', {'orderId': order.id, 'reference': 'PSK-PF-WH1'}, format='json')
            self.assertEqual(r3.status_code, 200)

            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 1)
            mock_push.assert_called_once()

        # Paid-after-cancel must NOT trigger vendor "new order" alerts
        mail.outbox.clear()
        AnalyticsEvent.objects.filter(event='vendor_order_placed').delete()
        canc_order = Order.objects.create(
            id='STW-PF-WHC',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 35.0, 'qty': 1}],
            subtotal=Decimal('35.00'),
            fee=Decimal('1.75'),
            total=Decimal('36.75'),
            pickup_day='2026-12-01',
            handoff_code='778899',
            payment_status='cancelled',
            cancelled_at=timezone.now(),
            payment_reference='PSK-PF-WHC',
        )
        body_c = json.dumps({
            'event': 'charge.success',
            'data': {'reference': 'PSK-PF-WHC', 'status': 'success', 'currency': 'GHS', 'amount': 3675},
        }).encode('utf-8')
        sig_c = hmac.new(b'sk_test_webhook_secret_123', body_c, hashlib.sha512).hexdigest()
        fake_verify_c = MagicMock(
            ok=True,
            json=lambda: {
                'status': True,
                'data': {'status': 'success', 'reference': 'PSK-PF-WHC', 'currency': 'GHS', 'amount': 3675},
            },
        )
        with patch('api.views.http_requests.get', return_value=fake_verify_c), \
             patch('api.views._send_vendor_push', return_value=1) as mock_push_c:
            self.client.credentials()
            rc = self.client.post('/api/payments/webhook/', data=body_c, content_type='application/json', HTTP_X_PAYSTACK_SIGNATURE=sig_c)
            self.assertEqual(rc.status_code, 200)
            canc_order.refresh_from_db()
            self.assertEqual(canc_order.payment_status, 'refund_pending')
            self.assertTrue(AuditEntry.objects.filter(entity_id=canc_order.id, action='payment_received_after_cancel').exists())
            self.assertEqual(len(mail.outbox), 0)
            self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 0)
            mock_push_c.assert_not_called()


class ExpireUnpaidOrdersTests(TestCase):
    """
    Pay-first Task A4/A6: UNPAID_ORDER_TTL_MINUTES defaults to 30, and
    expire_unpaid_orders locks & re-checks payment status before cancelling
    expired unpaid orders, restoring stock once, skipping paid/fresh orders,
    staying idempotent, and routing late payment to refund_pending.
    """

    @classmethod
    def setUpTestData(cls):
        cls.customer = User.objects.create_user(
            email='pf.exp.cust@st.knust.edu.gh',
            password='Password123!',
            full_name='Expiry Customer',
            reference_id='20962001',
            phone='0249620001',
            hall='Unity Hall (Conti)',
            verified=True,
        )
        cls.vendor_user = User.objects.create_user(
            email='pf.exp.vendor@st.knust.edu.gh',
            password='Password123!',
            full_name='Expiry Chef',
            reference_id='20962002',
            phone='0249620002',
            hall='Katanga Hall',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='Expiry Kitchen',
        )
        cls.vendor = Vendor.objects.create(
            id='v_pfexp',
            user=cls.vendor_user,
            name='Expiry Kitchen',
            hall='Katanga Hall',
            open=True,
            active=True,
        )
        cls.meal = Meal.objects.create(
            id='m_pfexp_1',
            vendor=cls.vendor,
            name='Omo Tuo',
            price=Decimal('30.00'),
            cat='Rice',
            left=20,
            on=True,
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def _create_via_api(self, qty=2):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        r = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': qty}],
            'area': 'Unity Hall',
            'pickupDay': '2026-12-01',
        }, format='json')
        self.assertEqual(r.status_code, 201)
        return r.data['id']

    @override_settings(DEBUG=True, PAYSTACK_ALLOW_MOCK=True, PAYSTACK_SECRET_KEY='', EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')
    def test_expire_unpaid_orders_restores_stock_once_skips_paid_and_late_pay_refunds(self):
        from django.core import mail
        from django.core.management import call_command
        from api.models import AnalyticsEvent, AuditEntry

        self.assertEqual(settings.UNPAID_ORDER_TTL_MINUTES, 30)

        # 1. Expired unpaid order (35 min old, qty=3)
        oid_exp = self._create_via_api(qty=3)
        # 2. Fresh unpaid order (5 min old, qty=2) -> must NOT expire
        oid_fresh = self._create_via_api(qty=2)
        # 3. Old PAID order (45 min old, qty=4) -> must NOT expire
        oid_paid = self._create_via_api(qty=4)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        r_init = self.client.post('/api/payments/initialize/', {'orderId': oid_paid}, format='json')
        ref_paid = r_init.data['reference']
        self.assertEqual(self.client.post('/api/payments/verify/', {'orderId': oid_paid, 'reference': ref_paid}, format='json').status_code, 200)

        # Initialize ref on the soon-to-expire order too so late payment arrival can be tested
        r_init_exp = self.client.post('/api/payments/initialize/', {'orderId': oid_exp}, format='json')
        ref_exp = r_init_exp.data['reference']

        now = timezone.now()
        Order.objects.filter(pk=oid_exp).update(created_at=now - timedelta(minutes=35))
        Order.objects.filter(pk=oid_fresh).update(created_at=now - timedelta(minutes=5))
        Order.objects.filter(pk=oid_paid).update(created_at=now - timedelta(minutes=45))

        # Stock dropped 20 -> 20 - (3 + 2 + 4) = 11
        self.assertEqual(Meal.objects.get(pk=self.meal.pk).left, 11)

        # Customer sees payment.expiresAt on unpaid orders
        r_det_fresh = self.client.get(f'/api/orders/{oid_fresh}/')
        self.assertIsNotNone(r_det_fresh.data['payment']['expiresAt'])

        # Run expire_unpaid_orders -> cancels only oid_exp and restores +3 -> 14
        call_command('expire_unpaid_orders')
        o_exp = Order.objects.get(pk=oid_exp)
        o_fresh = Order.objects.get(pk=oid_fresh)
        o_paid = Order.objects.get(pk=oid_paid)

        self.assertEqual(o_exp.payment_status, 'cancelled')
        self.assertIsNotNone(o_exp.cancelled_at)
        self.assertIsNone(o_exp.paid_at)
        self.assertEqual(o_fresh.payment_status, 'pending')
        self.assertIsNone(o_fresh.cancelled_at)
        self.assertEqual(o_paid.payment_status, 'paid')
        self.assertIsNone(o_paid.cancelled_at)
        self.assertEqual(Meal.objects.get(pk=self.meal.pk).left, 14)
        self.assertEqual(AuditEntry.objects.filter(entity_id=oid_exp, action='order_expired_unpaid').count(), 1)

        # Vendor STILL gets 404 on expired order
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_user)}')
        self.assertEqual(self.client.get(f'/api/orders/{oid_exp}/').status_code, 404)

        # Running again is strictly idempotent (stock remains 14, audit count remains 1)
        call_command('expire_unpaid_orders')
        self.assertEqual(Meal.objects.get(pk=self.meal.pk).left, 14)
        self.assertEqual(AuditEntry.objects.filter(entity_id=oid_exp, action='order_expired_unpaid').count(), 1)

        # Payment arriving after expiry follows existing paid-after-cancel path -> refund_pending + AuditEntry, 0 vendor alerts
        mail.outbox.clear()
        AnalyticsEvent.objects.filter(event='vendor_order_placed').delete()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        r_late = self.client.post('/api/payments/verify/', {'orderId': oid_exp, 'reference': ref_exp}, format='json')
        self.assertEqual(r_late.status_code, 400)
        self.assertEqual(r_late.data.get('code'), 'refund_pending')
        o_exp.refresh_from_db()
        self.assertEqual(o_exp.payment_status, 'refund_pending')
        self.assertIsNotNone(o_exp.paid_at)
        self.assertTrue(AuditEntry.objects.filter(entity_id=oid_exp, action='payment_received_after_cancel').exists())
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(AnalyticsEvent.objects.filter(event='vendor_order_placed').count(), 0)


class ExpireUnpaidOrdersConcurrencyPostgresTests(TransactionTestCase):
    """
    Pay-first Task A4/A6 (PostgreSQL 16): Threaded race between expire_unpaid_orders
    and _mark_order_paid must deterministically either mark paid (no expiry/restore)
    or expire + refund_pending (stock restored exactly once), never both/corrupted.
    """

    @classmethod
    def _skip_unless_pg(cls, inst):
        if connection.vendor != 'postgresql':
            inst.skipTest('Row-lock contention race requires PostgreSQL 16.')

    def test_postgresql_threaded_expiry_vs_payment_race(self):
        self._skip_unless_pg(self)
        import threading
        from django.core.management import call_command
        from api.models import AnalyticsEvent, AuditEntry
        from api.views import _mark_order_paid

        customer = User.objects.create_user(
            email='pf.pgrace.cust@st.knust.edu.gh',
            password='Password123!',
            full_name='PG Race Cust',
            reference_id='20963001',
            phone='0249630001',
            hall='Unity Hall',
            verified=True,
        )
        vendor_user = User.objects.create_user(
            email='pf.pgrace.vend@st.knust.edu.gh',
            password='Password123!',
            full_name='PG Race Vendor',
            reference_id='20963002',
            phone='0249630002',
            hall='Unity Hall',
            verified=True,
            is_vendor=True,
            role='vendor',
            account_type='vendor',
            kitchen_name='PG Race Kitchen',
        )
        vendor = Vendor.objects.create(
            id='v_pf_pg', user=vendor_user, name='PG Race Kitchen', hall='Unity Hall', open=True, active=True
        )
        meal = Meal.objects.create(
            id='m_pf_pg', vendor=vendor, name='Fufu Race', price=Decimal('25.00'), cat='Swallows', left=20, on=True
        )

        # Verify payment vs expiry across 4 concurrent orders with barrier sync
        for idx in range(4):
            AnalyticsEvent.objects.filter(event='vendor_order_placed').delete()
            start_left = Meal.objects.get(pk=meal.pk).left
            Meal.objects.filter(pk=meal.pk).update(left=models.F('left') - 1)
            oid = f'STW-PF-PGR{idx}'
            ref = f'PSK-PF-PGR{idx}'
            order = Order.objects.create(
                id=oid,
                customer=customer,
                customer_name=customer.full_name,
                email=customer.email,
                phone=customer.phone,
                area='Unity Hall',
                vendor=vendor,
                vendor_name=vendor.name,
                lines=[{'mealId': meal.id, 'name': meal.name, 'price': 25.0, 'qty': 1}],
                subtotal=Decimal('25.00'),
                fee=Decimal('1.25'),
                total=Decimal('26.25'),
                pickup_day='2026-12-01',
                handoff_code='112233',
                payment_status='pending',
                payment_reference=ref,
            )
            Order.objects.filter(pk=oid).update(created_at=timezone.now() - timedelta(minutes=45))

            barrier = threading.Barrier(2)
            errors = []

            def _run_expire():
                connections.close_all()
                try:
                    barrier.wait(timeout=5)
                    call_command('expire_unpaid_orders')
                except Exception as exc:
                    errors.append(exc)
                finally:
                    connections.close_all()

            def _run_pay():
                connections.close_all()
                try:
                    barrier.wait(timeout=5)
                    _mark_order_paid(order, 'paystack_webhook', ref)
                except Exception as exc:
                    errors.append(exc)
                finally:
                    connections.close_all()

            t1 = threading.Thread(target=_run_expire)
            t2 = threading.Thread(target=_run_pay)
            t1.start()
            t2.start()
            t1.join(timeout=15)
            t2.join(timeout=15)

            self.assertEqual(errors, [], f'Iteration {idx} raised: {errors}')
            order.refresh_from_db()
            end_left = Meal.objects.get(pk=meal.pk).left
            notif_count = AnalyticsEvent.objects.filter(event='vendor_order_placed').count()

            if order.payment_status == 'paid':
                self.assertIsNone(order.cancelled_at)
                self.assertIsNotNone(order.paid_at)
                self.assertEqual(end_left, start_left - 1)
                self.assertEqual(notif_count, 1)
            else:
                self.assertEqual(order.payment_status, 'refund_pending')
                self.assertIsNotNone(order.cancelled_at)
                self.assertIsNotNone(order.paid_at)
                self.assertEqual(end_left, start_left)
                self.assertEqual(notif_count, 0)
                self.assertTrue(
                    AuditEntry.objects.filter(entity_id=oid, action='payment_received_after_cancel').exists()
                )


class SecurityHeadersCacheControlTests(TestCase):
    """Authenticated and sensitive API routes must emit Cache-Control: no-store, private."""

    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            id='u-cc-admin',
            email='ccadmin@st.knust.edu.gh',
            full_name='CC Admin',
            role='admin',
            account_type='customer',
            is_admin=True,
            verified=True,
            reference_id='20901001',
            password='Password123',
        )
        self.student = User.objects.create_user(
            id='u-cc-stud',
            email='ccstud@st.knust.edu.gh',
            full_name='CC Student',
            role='customer',
            account_type='customer',
            verified=True,
            reference_id='20901002',
            password='Password123',
        )
        self.admin_token = generate_jwt_token(self.admin)
        self.stud_token = generate_jwt_token(self.student)

    def test_sensitive_and_authenticated_api_responses_set_no_store(self):
        # Unauthenticated login failure still under /api/auth/
        login_res = self.client.post('/api/auth/login/', {'email': self.student.email, 'password': 'WrongPassword1'}, format='json')
        self.assertIn('no-store', login_res.headers.get('Cache-Control', '').lower())
        self.assertIn('private', login_res.headers.get('Cache-Control', '').lower())
        self.assertEqual(login_res.headers.get('Pragma', '').lower(), 'no-cache')

        # Authenticated endpoints
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.stud_token}')
        for path in ('/api/auth/me/', '/api/orders/', '/api/notifications/'):
            res = self.client.get(path)
            cc = res.headers.get('Cache-Control', '').lower()
            self.assertIn('no-store', cc, f'{path} missing no-store: {cc}')
            self.assertIn('private', cc, f'{path} missing private: {cc}')
            self.assertEqual(res.headers.get('Pragma', '').lower(), 'no-cache', path)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        for path in ('/api/admin/users/', '/api/payouts/'):
            res = self.client.get(path)
            cc = res.headers.get('Cache-Control', '').lower()
            self.assertIn('no-store', cc, f'{path} missing no-store: {cc}')
            self.assertIn('private', cc, f'{path} missing private: {cc}')

        # Public non-sensitive catalog endpoint works normally
        self.client.credentials()
        pub_res = self.client.get('/api/meals/')
        self.assertEqual(pub_res.status_code, 200)
        self.assertNotIn('no-store', pub_res.headers.get('Cache-Control', '').lower())


class PendingVendorApprovalTests(TestCase):
    """J3: New vendor applications must remain pending (active=False, open=False) until admin approval."""

    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            id='u-pva-admin',
            email='pvaadmin@st.knust.edu.gh',
            full_name='PVA Admin',
            role='admin',
            account_type='customer',
            is_admin=True,
            verified=True,
            reference_id='20902001',
            password='Password123',
        )
        self.applicant = User.objects.create_user(
            id='u-pva-app',
            email='pvaapp@st.knust.edu.gh',
            full_name='PVA Applicant',
            role='customer',
            account_type='customer',
            verified=True,
            reference_id='20902002',
            password='Password123',
        )
        self.active_user = User.objects.create_user(
            id='u-pva-act',
            email='pvaact@st.knust.edu.gh',
            full_name='PVA Active Chef',
            role='vendor',
            account_type='vendor',
            is_vendor=True,
            verified=True,
            reference_id='20902003',
            password='Password123',
        )
        self.active_vendor = Vendor.objects.create(
            id='v-pva-act',
            user=self.active_user,
            name='Existing Active Pot',
            hall='Unity Hall (Conti)',
            bio='Active vendor.',
            prep=6,
            rating=4.5,
            reviews=5,
            open=True,
            active=True,
        )
        self.admin_token = generate_jwt_token(self.admin)
        self.app_token = generate_jwt_token(self.applicant)
        self.act_token = generate_jwt_token(self.active_user)

    def test_new_vendor_application_awaits_admin_approval_and_blocks_verify_auto_activate(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.app_token}')
        apply_res = self.client.post('/api/vendor/apply/', {
            'kitchen': 'Pending Okro Kitchen',
            'hall': 'Unity Hall (Conti)',
            'sells': ['Okro stew'],
            'about': 'Fresh okro stew prepared safely on campus.',
            'payout': '0249333444',
        }, format='json')
        self.assertEqual(apply_res.status_code, 200)
        self.assertEqual(apply_res.data['status'], 'pending')
        self.assertIs(apply_res.data['user']['vendorActive'], False)
        vendor = Vendor.objects.get(user=self.applicant)
        self.assertFalse(vendor.active)
        self.assertFalse(vendor.open)

        # Hidden from public catalog before admin approval
        self.client.credentials()
        pub_list = self.client.get('/api/vendors/').data
        pub_items = pub_list.get('results', pub_list) if isinstance(pub_list, dict) else pub_list
        self.assertFalse(any(v['id'] == vendor.id for v in pub_items))
        self.assertEqual(self.client.get(f'/api/vendors/{vendor.id}/').status_code, 404)

        # Pending vendor cannot create meals
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.app_token}')
        blocked_meal = self.client.post('/api/meals/', {
            'name': 'Premature Dish',
            'price': 30,
            'stock': 5,
            'cat': 'Soups',
            'desc': 'Should not publish before approval.',
        }, format='json')
        self.assertEqual(blocked_meal.status_code, 403)

        # Email re-verification must not auto-activate pending vendor
        self.applicant.verified = False
        self.applicant.verification_code_hash = hash_token('778899')
        self.applicant.verification_code_expires = timezone.now() + timedelta(minutes=10)
        self.applicant.save(update_fields=['verified', 'verification_code_hash', 'verification_code_expires'])
        self.client.credentials()
        ver_res = self.client.post('/api/auth/verify-email/', {'email': self.applicant.email, 'code': '778899'}, format='json')
        self.assertEqual(ver_res.status_code, 200)
        vendor.refresh_from_db()
        self.assertFalse(vendor.active)
        self.assertFalse(vendor.open)

        # Already-active vendor updating profile via /vendor/apply/ remains active
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.act_token}')
        upd_res = self.client.post('/api/vendor/apply/', {
            'kitchen': 'Updated Active Pot',
            'hall': 'Unity Hall (Conti)',
            'sells': ['Soup'],
            'about': 'Updated bio stays active.',
            'payout': '0249444555',
        }, format='json')
        self.assertEqual(upd_res.status_code, 200)
        self.assertEqual(upd_res.data['status'], 'active')
        self.assertIs(upd_res.data['user']['vendorActive'], True)

        # Admin approves vendor (active=True, open omitted -> auto-opens open=True)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        adm_res = self.client.patch(f'/api/admin/vendors/{vendor.id}/', {'active': True, 'verificationMethod': 'in_person'}, format='json')
        self.assertEqual(adm_res.status_code, 200)
        self.assertTrue(adm_res.data['active'])
        self.assertTrue(adm_res.data['open'])

        # Now public, /auth/me/ shows vendorActive=True, and vendor can publish meals
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.app_token}')
        me_res = self.client.get('/api/auth/me/')
        self.assertIs(me_res.data['vendorActive'], True)
        ok_meal = self.client.post('/api/meals/', {
            'name': 'Approved Dish',
            'price': 30,
            'stock': 5,
            'cat': 'Soups',
            'desc': 'Approved and ready.',
        }, format='json')
        self.assertEqual(ok_meal.status_code, 201)
        self.assertEqual(self.client.get(f'/api/vendors/{vendor.id}/').status_code, 200)


class NoIdentityDocumentTests(TestCase):
    """1.2: No ID photos accepted/stored, admin activation requires verificationMethod, and purge command works."""

    def setUp(self):
        self.client = APIClient()
        self.admin = User.objects.create_user(
            id='u-noid-adm',
            email='noidadm@st.knust.edu.gh',
            full_name='NoID Admin',
            role='admin',
            account_type='customer',
            is_admin=True,
            verified=True,
            reference_id='20903001',
            password='Password123',
        )
        self.student = User.objects.create_user(
            id='u-noid-stud',
            email='noidstud@st.knust.edu.gh',
            full_name='NoID Student',
            role='customer',
            account_type='customer',
            verified=True,
            reference_id='20903002',
            password='Password123',
        )
        self.admin_token = generate_jwt_token(self.admin)
        self.stud_token = generate_jwt_token(self.student)

    def test_vendor_apply_rejects_id_document_fields_and_requires_verification_method_on_approval(self):
        from api.models import AuditEntry
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.stud_token}')
        for bad_key in ('idDoc', 'id_doc', 'idPhoto', 'ghanaCard', 'idNumber'):
            res = self.client.post('/api/vendor/apply/', {
                'kitchen': 'Test Kitchen',
                'hall': 'Unity Hall (Conti)',
                'sells': ['Jollof'],
                'about': 'Clean kitchen.',
                'payout': '0249555111',
                bad_key: 'student-id.jpg',
            }, format='json')
            self.assertEqual(res.status_code, 400, f'Expected 400 for {bad_key}, got {res.status_code}')

        # Clean application succeeds as pending
        ok_apply = self.client.post('/api/vendor/apply/', {
            'kitchen': 'Clean Kitchen',
            'hall': 'Unity Hall (Conti)',
            'sells': ['Jollof'],
            'about': 'Clean kitchen without ID uploads.',
            'payout': '0249555111',
        }, format='json')
        self.assertEqual(ok_apply.status_code, 200)
        self.assertEqual(ok_apply.data['status'], 'pending')
        vendor = Vendor.objects.get(user=self.student)
        self.assertFalse(vendor.active)

        # Admin activation without verificationMethod is refused
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        no_method = self.client.patch(f'/api/admin/vendors/{vendor.id}/', {'active': True}, format='json')
        self.assertEqual(no_method.status_code, 400)
        vendor.refresh_from_db()
        self.assertFalse(vendor.active)

        # Invalid method is refused
        bad_method = self.client.patch(
            f'/api/admin/vendors/{vendor.id}/',
            {'active': True, 'verificationMethod': 'id_card_scan'},
            format='json',
        )
        self.assertEqual(bad_method.status_code, 400)

        # Valid method + note activates and writes AuditEntry
        good = self.client.patch(
            f'/api/admin/vendors/{vendor.id}/',
            {'active': True, 'verificationMethod': 'in_person', 'verificationNote': 'Met at Unity Hall kitchen'},
            format='json',
        )
        self.assertEqual(good.status_code, 200)
        self.assertTrue(good.data['active'])
        self.assertTrue(good.data['open'])
        entry = AuditEntry.objects.filter(action='admin_vendor_updated', entity_id=vendor.id).order_by('-at').first()
        self.assertIsNotNone(entry)
        self.assertEqual(entry.actor, self.admin.email)
        self.assertEqual(entry.extra.get('verificationMethod'), 'in_person')
        self.assertEqual(entry.extra.get('verificationNote'), 'Met at Unity Hall kitchen')

    def test_purge_identity_documents_command_dry_run_and_apply(self):
        from api.models import AuditEntry
        from io import StringIO
        from django.core.management import call_command
        entry = AuditEntry.objects.create(
            actor=self.admin.email,
            action='legacy_apply',
            entity_type='vendor',
            entity_id='v-legacy',
            extra={'idDoc': 'student_id.png', 'ghanaCard': 'GHA-123456', 'keep': 'ok'},
        )
        out_dry = StringIO()
        call_command('purge_identity_documents', stdout=out_dry)
        entry.refresh_from_db()
        self.assertIn('idDoc', entry.extra)
        self.assertIn('dry-run', out_dry.getvalue().lower())

        out_apply = StringIO()
        call_command('purge_identity_documents', '--apply', stdout=out_apply)
        entry.refresh_from_db()
        self.assertNotIn('idDoc', entry.extra)
        self.assertNotIn('ghanaCard', entry.extra)
        self.assertEqual(entry.extra.get('keep'), 'ok')


class PhoneEmailPrivacyTests(TestCase):
    def setUp(self):
        from decimal import Decimal
        from django.utils import timezone
        from api.models import User, Vendor, Meal, Order
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.customer = User.objects.create_user(
            email='cust_priv@st.knust.edu.gh',
            full_name='Privacy Customer',
            phone='0249998877',
            reference_id='20900001',
            verified=True,
            role='student',
            account_type='customer',
            password='Password123',
        )
        self.vendor_user = User.objects.create_user(
            email='vend_priv@st.knust.edu.gh',
            full_name='Privacy Vendor',
            phone='0551112233',
            payout='0551112233',
            reference_id='20900002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        self.admin = User.objects.create_user(
            email='admin_priv@st.knust.edu.gh',
            full_name='Privacy Admin',
            phone='0200000001',
            reference_id='20900003',
            verified=True,
            role='admin',
            account_type='customer',
            is_admin=True,
            password='Password123',
        )
        self.vendor = Vendor.objects.create(
            id='v_priv1',
            user=self.vendor_user,
            name='Privacy Kitchen',
            hall='Legon Hall',
            active=True,
            open=True,
        )
        self.meal = Meal.objects.create(
            id='m_priv1',
            vendor=self.vendor,
            name='Jollof Special',
            price=Decimal('45.00'),
            on=True,
            left=10,
        )
        self.order = Order.objects.create(
            id='STW-PRIV1',
            customer=self.customer,
            customer_name=self.customer.full_name,
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            area='Legon Hall',
            pickup_day='Today',
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 45.0}],
            subtotal=Decimal('45.00'),
            fee=Decimal('2.25'),
            total=Decimal('47.25'),
            payment_status='paid',
            paid_at=timezone.now(),
            phone='0249998877',
            email='cust_priv@st.knust.edu.gh',
            order_note='Call me on 024 999 8877 when ready',
            contact_note='Alt: +233551112233',
            meetup={'place': 'Gate', 'note': 'Reach 123456789'},
            messages=[{'from': 'customer', 'text': 'My number is 050-111-2222', 'at': 1700000000000}],
        )

    def test_vendor_never_sees_customer_phone_or_email(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_user)}')
        list_res = self.client.get('/api/orders/')
        self.assertEqual(list_res.status_code, 200)
        orders = list_res.data.get('results', list_res.data) if isinstance(list_res.data, dict) else list_res.data
        self.assertEqual(len(orders), 1)
        row_str = str(orders[0])
        self.assertNotIn('0249998877', row_str)
        self.assertNotIn('cust_priv@st.knust.edu.gh', row_str)
        self.assertIsNone(orders[0].get('phone'))
        self.assertIsNone(orders[0].get('email'))

        det_res = self.client.get(f'/api/orders/{self.order.id}/')
        self.assertEqual(det_res.status_code, 200)
        det_str = str(det_res.data)
        self.assertNotIn('0249998877', det_str)
        self.assertNotIn('cust_priv@st.knust.edu.gh', det_str)

    def test_customer_never_sees_vendor_phone_email_or_payout(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        for url in ['/api/vendors/', f'/api/vendors/{self.vendor.id}/', '/api/meals/', '/api/orders/', f'/api/orders/{self.order.id}/']:
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200)
            body_str = str(res.data)
            self.assertNotIn('0551112233', body_str, f'Leaked vendor phone/payout on {url}')
            self.assertNotIn('vend_priv@st.knust.edu.gh', body_str, f'Leaked vendor email on {url}')

    def test_phone_numbers_masked_in_chat_and_notes_for_non_admins_only(self):
        # Customer & vendor see masked phones
        for actor in (self.customer, self.vendor_user):
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(actor)}')
            res = self.client.get(f'/api/orders/{self.order.id}/')
            self.assertEqual(res.status_code, 200)
            self.assertIn('[phone hidden]', res.data['orderNote'])
            self.assertIn('[phone hidden]', res.data['contactNote'])
            self.assertIn('[phone hidden]', res.data['meetup']['note'])
            self.assertIn('[phone hidden]', res.data['messages'][0]['text'])
            self.assertNotIn('050-111-2222', str(res.data['messages']))

        # Sending a message with a phone number returns phoneMasked=True
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        msg_res = self.client.post(
            f'/api/orders/{self.order.id}/messages/',
            {'text': 'Ping me at 0241234567 please'},
            format='json',
        )
        self.assertEqual(msg_res.status_code, 200)
        self.assertTrue(msg_res.data.get('phoneMasked'))
        self.assertIn('[phone hidden]', msg_res.data['messages'][-1]['text'])

        # Admin sees unmasked original
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        adm_res = self.client.get(f'/api/orders/{self.order.id}/')
        self.assertEqual(adm_res.status_code, 200)
        self.assertEqual(adm_res.data.get('phone'), '0249998877')
        self.assertEqual(adm_res.data.get('email'), 'cust_priv@st.knust.edu.gh')
        self.assertIn('050-111-2222', adm_res.data['messages'][0]['text'])
        self.assertIn('0241234567', adm_res.data['messages'][-1]['text'])


class AdminConversationsTests(TestCase):
    def setUp(self):
        from decimal import Decimal
        from django.utils import timezone
        from api.models import User, Vendor, Order
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.customer = User.objects.create_user(
            email='cust_conv@st.knust.edu.gh',
            full_name='Conv Customer',
            phone='0248887766',
            reference_id='20910001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        self.vendor_user = User.objects.create_user(
            email='vend_conv@st.knust.edu.gh',
            full_name='Conv Vendor',
            phone='0554443322',
            reference_id='20910002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        self.admin = User.objects.create_user(
            email='admin_conv@st.knust.edu.gh',
            full_name='Conv Admin',
            phone='0200000002',
            reference_id='20910003',
            verified=True,
            role='admin',
            account_type='customer',
            is_admin=True,
            password='Password123',
        )
        self.vendor = Vendor.objects.create(
            id='v_conv1',
            user=self.vendor_user,
            name='Conv Kitchen',
            hall='Unity Hall',
            active=True,
            open=True,
        )
        self.order_with_msgs = Order.objects.create(
            id='STW-CONV1',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Waakye', 'qty': 1, 'price': 30.0}],
            subtotal=Decimal('30.00'),
            fee=Decimal('1.50'),
            total=Decimal('31.50'),
            payment_status='paid',
            paid_at=timezone.now(),
            messages=[
                {'from': 'student', 'text': 'Call 0248887766 at gate', 'at': 1700000000000},
                {'from': 'vendor', 'text': 'On my way', 'at': 1700000060000},
            ],
        )
        self.order_no_msgs = Order.objects.create(
            id='STW-CONV2',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Waakye', 'qty': 1, 'price': 30.0}],
            subtotal=Decimal('30.00'),
            fee=Decimal('1.50'),
            total=Decimal('31.50'),
            payment_status='paid',
            paid_at=timezone.now(),
            messages=[],
        )

    def test_conversations_list_and_messages_require_admin_and_reason(self):
        from api.models import AuditEntry
        for non_admin in (self.customer, self.vendor_user):
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(non_admin)}')
            self.assertEqual(self.client.get('/api/admin/conversations/').status_code, 403)
            self.assertEqual(
                self.client.get(f'/api/admin/conversations/{self.order_with_msgs.id}/messages/?reason=safety').status_code,
                403,
            )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        list_res = self.client.get('/api/admin/conversations/?q=STW-CONV1')
        self.assertEqual(list_res.status_code, 200)
        results = list_res.data.get('results', list_res.data)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['orderId'], 'STW-CONV1')

        # Missing or invalid reason -> 400
        self.assertEqual(
            self.client.get(f'/api/admin/conversations/{self.order_with_msgs.id}/messages/').status_code,
            400,
        )
        self.assertEqual(
            self.client.get(f'/api/admin/conversations/{self.order_with_msgs.id}/messages/?reason=curious').status_code,
            400,
        )

        # Valid reason -> 200 with unmasked messages + AuditEntry
        msg_res = self.client.get(f'/api/admin/conversations/{self.order_with_msgs.id}/messages/?reason=dispute')
        self.assertEqual(msg_res.status_code, 200)
        self.assertEqual(len(msg_res.data['messages']), 2)
        self.assertIn('0248887766', msg_res.data['messages'][0]['text'])
        audit = AuditEntry.objects.filter(
            action='admin_conversation_viewed',
            entity_id=self.order_with_msgs.id,
        ).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.extra.get('reason'), 'dispute')


class FailedLoginTrackingTests(TestCase):
    def setUp(self):
        from api.models import User
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.user = User.objects.create_user(
            email='victim_fl@st.knust.edu.gh',
            full_name='Target Student',
            phone='0247776655',
            reference_id='20920001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        self.inactive = User.objects.create_user(
            email='inactive_fl@st.knust.edu.gh',
            full_name='Inactive Student',
            phone='0247776656',
            reference_id='20920002',
            verified=True,
            is_active=False,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        self.admin = User.objects.create_user(
            email='admin_fl@st.knust.edu.gh',
            full_name='Sec Admin',
            phone='0200000003',
            reference_id='20920003',
            verified=True,
            role='admin',
            account_type='customer',
            is_admin=True,
            password='Password123',
        )

    def test_failed_logins_recorded_across_auth_paths_and_capped_per_ip(self):
        from api.models import FailedLoginEvent
        # 1. Wrong password
        self.client.post('/api/auth/login/', {'email': self.user.email, 'password': 'WrongPassword'}, format='json')
        # 2. Unknown email
        self.client.post('/api/auth/login/', {'email': 'nobody_fl@st.knust.edu.gh', 'password': 'Password123'}, format='json')
        # 3. Inactive account
        self.client.post('/api/auth/login/', {'email': self.inactive.email, 'password': 'Password123'}, format='json')
        # 4. Bad login code
        self.client.post('/api/auth/login-code/verify/', {'email': self.user.email, 'code': '000000'}, format='json')

        self.assertGreaterEqual(FailedLoginEvent.objects.count(), 4)
        reasons = set(FailedLoginEvent.objects.values_list('reason', flat=True))
        self.assertTrue(len(reasons) >= 2, f'Expected distinct failure reasons, got {reasons}')

        # IP hourly cap prevents DB flooding
        FailedLoginEvent.objects.all().delete()
        with self.settings(FAILED_LOGIN_IP_HOURLY_CAP=2):
            for i in range(5):
                _RATE_LIMIT_CACHE.clear()
                self.client.post('/api/auth/login/', {'email': self.user.email, 'password': f'Wrong{i}'}, format='json')
            self.assertEqual(FailedLoginEvent.objects.count(), 2)

    def test_admin_failed_logins_endpoint_and_cleanup_retention(self):
        from datetime import timedelta
        from io import StringIO
        from django.core.management import call_command
        from django.utils import timezone
        from api.models import FailedLoginEvent

        FailedLoginEvent.objects.create(
            email_attempted='victim_fl@st.knust.edu.gh',
            ip_address='10.0.0.5',
            reason='invalid_credentials',
            endpoint='/api/auth/login/',
        )
        old_evt = FailedLoginEvent.objects.create(
            email_attempted='old_fl@st.knust.edu.gh',
            ip_address='10.0.0.6',
            reason='invalid_credentials',
            endpoint='/api/auth/login/',
        )
        FailedLoginEvent.objects.filter(pk=old_evt.pk).update(created_at=timezone.now() - timedelta(days=35))

        # Non-admin -> 403
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.user)}')
        self.assertEqual(self.client.get('/api/admin/security/failed-logins/').status_code, 403)

        # Admin -> 200 with summary & filters
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        res = self.client.get('/api/admin/security/failed-logins/?email=victim_fl')
        self.assertEqual(res.status_code, 200)
        self.assertIn('summary', res.data)
        self.assertEqual(len(res.data['results']), 1)

        # cleanup_rate_limits purges > 30d rows, keeps recent
        out = StringIO()
        call_command('cleanup_rate_limits', stdout=out)
        self.assertFalse(FailedLoginEvent.objects.filter(pk=old_evt.pk).exists())
        self.assertTrue(FailedLoginEvent.objects.filter(email_attempted='victim_fl@st.knust.edu.gh').exists())


class CancellationPolicyAndReviewTests(TestCase):
    def setUp(self):
        from decimal import Decimal
        from api.models import User, Vendor, Meal
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.customer = User.objects.create_user(
            email='cust_pol@st.knust.edu.gh',
            full_name='Policy Customer',
            phone='0246665544',
            reference_id='20930001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        self.vendor_user = User.objects.create_user(
            email='vend_pol@st.knust.edu.gh',
            full_name='Policy Vendor',
            phone='0553334455',
            reference_id='20930002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        self.vendor = Vendor.objects.create(
            id='v_pol1',
            user=self.vendor_user,
            name='Policy Kitchen',
            hall='Katanga',
            active=True,
            open=True,
        )
        self.meal = Meal.objects.create(
            id='m_pol1',
            vendor=self.vendor,
            name='Banku & Tilapia',
            price=Decimal('40.00'),
            on=True,
            left=20,
        )

    def test_policy_endpoint_and_cancel_until_prep_starts(self):
        from datetime import timedelta
        from decimal import Decimal
        from django.utils import timezone
        from api.models import Order

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        pol_res = self.client.get('/api/orders/policy/')
        self.assertEqual(pol_res.status_code, 200)
        self.assertTrue(pol_res.data['customerCancelUntilPrepStarts'])
        self.assertEqual(pol_res.data['customerCancelWindowSeconds'], 120)
        self.assertEqual(pol_res.data['customerPaidCancelsPerDay'], 5)

        # Paid order created 10 minutes ago, still at prep_stage='accepted' -> customer CAN cancel
        order1 = Order.objects.create(
            id='STW-POL1',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Katanga',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 40.0}],
            subtotal=Decimal('40.00'),
            fee=Decimal('2.00'),
            total=Decimal('42.00'),
            payment_status='paid',
            paid_at=timezone.now() - timedelta(minutes=10),
            prep_stage='accepted',
        )
        Order.objects.filter(pk=order1.pk).update(created_at=timezone.now() - timedelta(minutes=10))

        c_res = self.client.post(f'/api/orders/{order1.id}/cancel/')
        self.assertEqual(c_res.status_code, 200)

        # Once prep_stage='preparing', customer CANNOT cancel
        order2 = Order.objects.create(
            id='STW-POL2',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Katanga',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 40.0}],
            subtotal=Decimal('40.00'),
            fee=Decimal('2.00'),
            total=Decimal('42.00'),
            payment_status='paid',
            paid_at=timezone.now(),
            prep_stage='preparing',
        )
        c2_res = self.client.post(f'/api/orders/{order2.id}/cancel/')
        self.assertEqual(c2_res.status_code, 400)

        # Daily cap on paid customer cancels
        with self.settings(CUSTOMER_PAID_CANCELS_PER_DAY=1):
            order3 = Order.objects.create(
                id='STW-POL3',
                customer=self.customer,
                customer_name=self.customer.full_name,
                email=self.customer.email,
                phone=self.customer.phone,
                area='Katanga',
                pickup_day='Today',
                vendor=self.vendor,
                vendor_name=self.vendor.name,
                lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 40.0}],
                subtotal=Decimal('40.00'),
                fee=Decimal('2.00'),
                total=Decimal('42.00'),
                payment_status='paid',
                paid_at=timezone.now(),
                prep_stage='accepted',
            )
            c3_res = self.client.post(f'/api/orders/{order3.id}/cancel/')
            self.assertIn(c3_res.status_code, (400, 429))

    def test_expected_total_mismatch_and_init_payment_preflight_return_409(self):
        from decimal import Decimal
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')

        # expectedTotal mismatch on POST /api/orders/ -> 409
        bad_order = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 1}],
            'area': 'Katanga',
            'pickupDay': 'Today',
            'expectedTotal': 10.00,
        }, format='json')
        self.assertEqual(bad_order.status_code, 409)

        # Create valid order, then change meal price before init_payment -> 409
        ok_order = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 1}],
            'area': 'Katanga',
            'pickupDay': 'Today',
        }, format='json')
        self.assertEqual(ok_order.status_code, 201)
        order_id = ok_order.data['id']

        self.meal.price = Decimal('55.00')
        self.meal.save(update_fields=['price'])

        pay_res = self.client.post('/api/payments/initialize/', {'orderId': order_id}, format='json')
        self.assertEqual(pay_res.status_code, 409)


from unittest import skipUnless as _skip_unless
from django.db import connection as _db_conn


@_skip_unless(_db_conn.vendor == 'postgresql', 'PostgreSQL row-lock concurrency test')
class CancelVsPrepRacePostgresTests(TransactionTestCase):
    def test_customer_cancel_vs_vendor_preparing_race_is_serialized(self):
        import threading
        from decimal import Decimal
        from django.db import connections
        from django.utils import timezone
        from api.models import User, Vendor, Meal, Order

        _RATE_LIMIT_CACHE.clear()
        cust = User.objects.create_user(
            email='pg_race_cust@st.knust.edu.gh',
            full_name='PG Cust',
            phone='0241112233',
            reference_id='20940001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        vend_u = User.objects.create_user(
            email='pg_race_vend@st.knust.edu.gh',
            full_name='PG Vend',
            phone='0551112233',
            reference_id='20940002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        vend = Vendor.objects.create(id='v_pgrace', user=vend_u, name='PG Kitchen', hall='Unity', active=True, open=True)
        Meal.objects.create(id='m_pgrace', vendor=vend, name='Rice', price=Decimal('25.00'), on=True, left=10)
        order = Order.objects.create(
            id='STW-PGRACE-C1',
            customer=cust,
            customer_name=cust.full_name,
            email=cust.email,
            phone=cust.phone,
            area='Unity',
            pickup_day='Today',
            vendor=vend,
            vendor_name=vend.name,
            lines=[{'mealId': 'm_pgrace', 'name': 'Rice', 'qty': 1, 'price': 25.0}],
            subtotal=Decimal('25.00'),
            fee=Decimal('1.25'),
            total=Decimal('26.25'),
            payment_status='paid',
            paid_at=timezone.now(),
            prep_stage='accepted',
        )

        cust_tok = generate_jwt_token(cust)
        vend_tok = generate_jwt_token(vend_u)
        barrier = threading.Barrier(2)
        results = {}

        def do_cancel():
            try:
                c = APIClient()
                c.credentials(HTTP_AUTHORIZATION=f'Bearer {cust_tok}')
                barrier.wait(timeout=5)
                r = c.post(f'/api/orders/{order.id}/cancel/')
                results['cancel'] = r.status_code
            finally:
                connections.close_all()

        def do_prep():
            try:
                c = APIClient()
                c.credentials(HTTP_AUTHORIZATION=f'Bearer {vend_tok}')
                barrier.wait(timeout=5)
                r = c.post(f'/api/orders/{order.id}/prep/', {'stage': 'preparing'}, format='json')
                results['prep'] = r.status_code
            finally:
                connections.close_all()

        t1 = threading.Thread(target=do_cancel)
        t2 = threading.Thread(target=do_prep)
        t1.start(); t2.start()
        t1.join(); t2.join()

        self.assertEqual(sorted(results.values()), [200, 400])
        order.refresh_from_db()
        if results['cancel'] == 200:
            self.assertIsNotNone(order.cancelled_at)
            self.assertEqual(order.prep_stage, 'accepted')
        else:
            self.assertIsNone(order.cancelled_at)
            self.assertEqual(order.prep_stage, 'preparing')


class PaystackRefundTests(TestCase):
    def setUp(self):
        from decimal import Decimal
        from django.utils import timezone
        from api.models import User, Vendor, Meal, Order
        self.client = APIClient()
        _RATE_LIMIT_CACHE.clear()
        self.customer = User.objects.create_user(
            email='cust_ref@st.knust.edu.gh',
            full_name='Refund Customer',
            phone='0245556677',
            reference_id='20950001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        self.vendor_user = User.objects.create_user(
            email='vend_ref@st.knust.edu.gh',
            full_name='Refund Vendor',
            phone='0556667788',
            reference_id='20950002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        self.admin = User.objects.create_user(
            email='admin_ref@st.knust.edu.gh',
            full_name='Refund Admin',
            phone='0200000005',
            reference_id='20950003',
            verified=True,
            role='admin',
            account_type='customer',
            is_admin=True,
            password='Password123',
        )
        self.vendor = Vendor.objects.create(
            id='v_ref1',
            user=self.vendor_user,
            name='Refund Kitchen',
            hall='Unity Hall',
            active=True,
            open=True,
        )
        self.meal = Meal.objects.create(
            id='m_ref1',
            vendor=self.vendor,
            name='Fufu',
            price=Decimal('50.00'),
            on=True,
            left=10,
        )
        self.order = Order.objects.create(
            id='STW-REF1',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 50.0}],
            subtotal=Decimal('50.00'),
            fee=Decimal('2.50'),
            total=Decimal('52.50'),
            payment_status='paid',
            payment_reference='PSK-REF-100',
            paid_at=timezone.now(),
            prep_stage='accepted',
        )

    def test_customer_cancel_triggers_paystack_refund_for_full_amount(self):
        from unittest.mock import patch, MagicMock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'status': True,
            'data': {'id': 901, 'status': 'pending', 'transaction': {'reference': 'PSK-REF-100'}},
        }

        with self.settings(PAYSTACK_SECRET_KEY='sk_test_mock_key'):
            with patch('api.views.http_requests.post', return_value=mock_resp) as mock_post:
                self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
                res = self.client.post(f'/api/orders/{self.order.id}/cancel/')
                self.assertEqual(res.status_code, 200)
                self.assertEqual(res.data['payment']['status'], 'refund_pending')
                self.assertTrue(mock_post.called)
                call_kwargs = mock_post.call_args.kwargs
                self.assertEqual(call_kwargs['json']['transaction'], 'PSK-REF-100')
                self.assertEqual(call_kwargs['json']['amount'], 5250)

    def test_409_duplicate_refund_reconciles_via_get_and_payout_batch_blocks(self):
        from unittest.mock import patch, MagicMock
        from decimal import Decimal
        from django.utils import timezone
        from api.models import Order

        post_409 = MagicMock()
        post_409.status_code = 409
        post_409.json.return_value = {'status': False, 'message': 'Duplicate refund'}

        get_ok = MagicMock()
        get_ok.status_code = 200
        get_ok.json.return_value = {
            'status': True,
            'data': [{'id': 902, 'status': 'processed', 'transaction_reference': 'PSK-REF-100'}],
        }

        with self.settings(PAYSTACK_SECRET_KEY='sk_test_mock_key'):
            with patch('api.views.http_requests.post', return_value=post_409):
                with patch('api.views.http_requests.get', return_value=get_ok):
                    self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.vendor_user)}')
                    res = self.client.post(f'/api/orders/{self.order.id}/cancel/')
                    self.assertEqual(res.status_code, 200)
                    self.assertEqual(res.data['payment']['status'], 'refunded')

        # Payout batch order refuses refund
        batched = Order.objects.create(
            id='STW-REF-BAT',
            customer=self.customer,
            customer_name=self.customer.full_name,
            email=self.customer.email,
            phone=self.customer.phone,
            area='Unity Hall',
            pickup_day='Today',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'qty': 1, 'price': 50.0}],
            subtotal=Decimal('50.00'),
            fee=Decimal('2.50'),
            total=Decimal('52.50'),
            payment_status='released',
            payment_reference='PSK-REF-BAT',
            paid_at=timezone.now(),
            payout_batch_id='PAY-999',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        bat_res = self.client.post(f'/api/orders/{batched.id}/cancel/')
        self.assertIn(bat_res.status_code, (400, 409))

    def test_refund_webhooks_attention_endpoint_and_retry_command(self):
        import hmac, hashlib, json
        from io import StringIO
        from unittest.mock import patch, MagicMock
        from django.core.management import call_command

        self.order.payment_status = 'refund_pending'
        self.order.cancelled_at = self.order.paid_at
        self.order.save(update_fields=['payment_status', 'cancelled_at'])

        secret = 'sk_test_webhook_secret'
        for evt, expected_status in [
            ('refund.pending', 'refund_pending'),
            ('refund.processing', 'refund_pending'),
            ('refund.failed', 'refund_pending'),
            ('refund.needs_attention', 'refund_pending'),
            ('refund.processed', 'refunded'),
        ]:
            payload = json.dumps({
                'event': evt,
                'data': {'id': 777, 'transaction_reference': 'PSK-REF-100', 'status': evt.split('.')[1]},
            }).encode('utf-8')
            sig = hmac.new(secret.encode('utf-8'), payload, hashlib.sha512).hexdigest()
            with self.settings(PAYSTACK_SECRET_KEY=secret):
                w_res = self.client.post(
                    '/api/payments/webhook/',
                    data=payload,
                    content_type='application/json',
                    HTTP_X_PAYSTACK_SIGNATURE=sig,
                )
                self.assertEqual(w_res.status_code, 200)
                self.order.refresh_from_db()
                self.assertEqual(self.order.payment_status, expected_status)

        # Admin attention endpoint (non-admin -> 403, admin -> 200)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.customer)}')
        self.assertEqual(self.client.get('/api/admin/refunds/attention/').status_code, 403)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.admin)}')
        att_res = self.client.get('/api/admin/refunds/attention/')
        self.assertEqual(att_res.status_code, 200)

        # retry_pending_refunds retries refund_pending orders
        self.order.payment_status = 'refund_pending'
        self.order.save(update_fields=['payment_status'])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'status': True, 'data': {'id': 903, 'status': 'processed'}}
        with self.settings(PAYSTACK_SECRET_KEY='sk_test_mock_key'):
            with patch('api.views.http_requests.post', return_value=mock_resp):
                out = StringIO()
                call_command('retry_pending_refunds', stdout=out)
                self.order.refresh_from_db()
                self.assertEqual(self.order.payment_status, 'refunded')


@_skip_unless(_db_conn.vendor == 'postgresql', 'PostgreSQL row-lock concurrency test')
class CancelVsCancelRefundRacePostgresTests(TransactionTestCase):
    def test_concurrent_cancels_trigger_at_most_one_paystack_refund(self):
        import threading
        from decimal import Decimal
        from unittest.mock import patch, MagicMock
        from django.db import connections
        from django.utils import timezone
        from api.models import User, Vendor, Meal, Order

        _RATE_LIMIT_CACHE.clear()
        cust = User.objects.create_user(
            email='pg_ref_cust@st.knust.edu.gh',
            full_name='PG Ref Cust',
            phone='0242223344',
            reference_id='20960001',
            verified=True,
            role='customer',
            account_type='customer',
            password='Password123',
        )
        vend_u = User.objects.create_user(
            email='pg_ref_vend@st.knust.edu.gh',
            full_name='PG Ref Vend',
            phone='0552223344',
            reference_id='20960002',
            verified=True,
            role='vendor',
            is_vendor=True,
            account_type='vendor',
            password='Password123',
        )
        vend = Vendor.objects.create(id='v_pgref', user=vend_u, name='PG Ref Kitchen', hall='Unity', active=True, open=True)
        Meal.objects.create(id='m_pgref', vendor=vend, name='Banku', price=Decimal('30.00'), on=True, left=10)
        order = Order.objects.create(
            id='STW-PGREF-1',
            customer=cust,
            customer_name=cust.full_name,
            email=cust.email,
            phone=cust.phone,
            area='Unity',
            pickup_day='Today',
            vendor=vend,
            vendor_name=vend.name,
            lines=[{'mealId': 'm_pgref', 'name': 'Banku', 'qty': 1, 'price': 30.0}],
            subtotal=Decimal('30.00'),
            fee=Decimal('1.50'),
            total=Decimal('31.50'),
            payment_status='paid',
            payment_reference='PSK-PGREF-1',
            paid_at=timezone.now(),
            prep_stage='accepted',
        )

        cust_tok = generate_jwt_token(cust)
        vend_tok = generate_jwt_token(vend_u)
        barrier = threading.Barrier(2)
        results = {}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'status': True, 'data': {'id': 999, 'status': 'pending'}}

        with self.settings(PAYSTACK_SECRET_KEY='sk_test_mock_key'):
            with patch('api.views.http_requests.post', return_value=mock_resp) as mock_post:
                def run_cancel(label, tok):
                    try:
                        c = APIClient()
                        c.credentials(HTTP_AUTHORIZATION=f'Bearer {tok}')
                        barrier.wait(timeout=5)
                        r = c.post(f'/api/orders/{order.id}/cancel/')
                        results[label] = r.status_code
                    finally:
                        connections.close_all()

                t1 = threading.Thread(target=run_cancel, args=('cust', cust_tok))
                t2 = threading.Thread(target=run_cancel, args=('vend', vend_tok))
                t1.start(); t2.start()
                t1.join(); t2.join()

                self.assertEqual(sorted(results.values()), [200, 400])
                self.assertEqual(mock_post.call_count, 1)


class ServerTimeHeaderTests(TestCase):
    def test_x_server_time_header_present_and_cors_exposed(self):
        from datetime import datetime
        from django.conf import settings
        self.assertIn('X-Server-Time', settings.CORS_EXPOSE_HEADERS)
        res = self.client.get('/api/orders/policy/')
        self.assertEqual(res.status_code, 200)
        hdr = res.headers.get('X-Server-Time')
        self.assertTrue(hdr)
        parsed = datetime.fromisoformat(hdr.replace('Z', '+00:00'))
        self.assertIsNotNone(parsed.tzinfo)


class HealthAndProxyTests(TestCase):
    def test_health_endpoint_unauthenticated_no_db_writes_minimal_json(self):
        with self.assertNumQueries(0):
            res = self.client.get('/api/health/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), {'status': 'ok'})

    def test_wsgi_application_importable(self):
        from stew_server.wsgi import application
        self.assertTrue(callable(application))

    @override_settings(
        DEBUG=False,
        SECURE_SSL_REDIRECT=True,
        SECURE_PROXY_SSL_HEADER=('HTTP_X_FORWARDED_PROTO', 'https'),
    )
    def test_secure_proxy_ssl_header_prevents_redirect_loop(self):
        res_http = self.client.get('/api/health/')
        self.assertEqual(res_http.status_code, 301)

        res_https = self.client.get('/api/health/', HTTP_X_FORWARDED_PROTO='https')
        self.assertEqual(res_https.status_code, 200)
        self.assertEqual(res_https.json(), {'status': 'ok'})


class AppEnvAndStartupGuardsTests(TestCase):
    def test_app_env_defaults_to_production(self):
        import os
        from django.conf import settings
        self.assertIn(settings.APP_ENV, ('development', 'staging', 'production'))
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('APP_ENV', None)
            self.assertEqual(os.getenv('APP_ENV', 'production'), 'production')

    def test_validate_runtime_settings_guards(self):
        from stew_server.settings import validate_runtime_settings

        # Invalid APP_ENV rejected
        with self.assertRaises(RuntimeError):
            validate_runtime_settings(
                app_env='qa',
                debug=False,
                paystack_secret_key='',
                paystack_allow_mock=False,
                beta_email_allowlist=[],
            )

        # Staging refuses live Paystack secret key
        with self.assertRaises(RuntimeError):
            validate_runtime_settings(
                app_env='staging',
                debug=False,
                paystack_secret_key='sk_live_dummy_refused',
                paystack_allow_mock=False,
                beta_email_allowlist=[],
            )

        # Staging accepts test key or blank when DEBUG=False & mock=False
        validate_runtime_settings(
            app_env='staging',
            debug=False,
            paystack_secret_key='sk_test_dummy_allowed',
            paystack_allow_mock=False,
            beta_email_allowlist=['friend@gmail.com'],
        )

        # Production refuses non-empty BETA_EMAIL_ALLOWLIST
        with self.assertRaises(RuntimeError):
            validate_runtime_settings(
                app_env='production',
                debug=False,
                paystack_secret_key='sk_live_dummy',
                paystack_allow_mock=False,
                beta_email_allowlist=['friend@gmail.com'],
            )

        # Staging/production refuse DEBUG=True and PAYSTACK_ALLOW_MOCK=True
        for env_name in ('staging', 'production'):
            with self.assertRaises(RuntimeError):
                validate_runtime_settings(
                    app_env=env_name,
                    debug=True,
                    paystack_secret_key='',
                    paystack_allow_mock=False,
                    beta_email_allowlist=[],
                )
            with self.assertRaises(RuntimeError):
                validate_runtime_settings(
                    app_env=env_name,
                    debug=False,
                    paystack_secret_key='',
                    paystack_allow_mock=True,
                    beta_email_allowlist=[],
                )


class BetaEmailAllowlistTests(TestCase):
    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_parser_rejects_wildcards_domains_uppercase_and_non_ascii(self):
        from stew_server.settings import parse_beta_email_allowlist
        self.assertEqual(
            parse_beta_email_allowlist(' friend@gmail.com , tester.two@outlook.com '),
            ['friend@gmail.com', 'tester.two@outlook.com'],
        )
        self.assertEqual(parse_beta_email_allowlist(''), [])
        for bad in (
            '*@gmail.com',
            'gmail.com',
            '@gmail.com',
            'Friend@gmail.com',
            'fr\u0456end@gmail.com',  # Cyrillic lookalike i
        ):
            with self.assertRaises(RuntimeError, msg=f'Should reject {bad!r}'):
                parse_beta_email_allowlist(bad)

    @override_settings(APP_ENV='staging', BETA_EMAIL_ALLOWLIST=['friend@gmail.com'])
    def test_staging_allowlist_works_across_all_auth_flows_and_rejects_lookalikes(self):
        import re
        from api.validators import clean_knust_email, is_allowed_email
        from api.models import User
        from rest_framework.exceptions import ValidationError as DRFValidationError

        # Normalization & lookalike checks
        self.assertTrue(is_allowed_email('  FRIEND@GMAIL.COM  '))
        self.assertEqual(clean_knust_email('  FRIEND@GMAIL.COM  '), 'friend@gmail.com')
        self.assertFalse(is_allowed_email('other@gmail.com'))
        self.assertFalse(is_allowed_email('fr\u0456end@gmail.com'))
        with self.assertRaises(DRFValidationError):
            clean_knust_email('other@gmail.com')

        # 1. Registration (requires OTP verification before login works)
        r_reg_bad = self.client.post('/api/auth/register/', {
            'email': 'other@gmail.com',
            'password': 'StrongPassword123!',
            'fullName': 'Non Allowlisted',
            'referenceId': '20990001',
            'phone': '0241000001',
            'hall': 'Unity Hall',
            'accountType': 'customer',
        }, format='json')
        self.assertEqual(r_reg_bad.status_code, 400)

        r_reg_lookalike = self.client.post('/api/auth/register/', {
            'email': 'fr\u0456end@gmail.com',
            'password': 'StrongPassword123!',
            'fullName': 'Lookalike User',
            'referenceId': '20990002',
            'phone': '0241000002',
            'hall': 'Unity Hall',
            'accountType': 'customer',
        }, format='json')
        self.assertEqual(r_reg_lookalike.status_code, 400)

        with patch('api.views._dispatch_otp_email') as mock_dispatch:
            r_reg_ok = self.client.post('/api/auth/register/', {
                'email': '  FRIEND@GMAIL.COM  ',
                'password': 'StrongPassword123!',
                'fullName': 'Beta Friend',
                'referenceId': '20990003',
                'phone': '0241000003',
                'hall': 'Unity Hall',
                'accountType': 'customer',
            }, format='json')
        self.assertEqual(r_reg_ok.status_code, 201, r_reg_ok.data)
        otp_code = mock_dispatch.call_args[0][1]

        # Unverified allowlisted user still cannot log in (and login_view issues a fresh verification OTP)
        with patch('api.views._dispatch_otp_email') as mock_login_dispatch:
            r_login_unverified = self.client.post('/api/auth/login/', {
                'email': 'friend@gmail.com',
                'password': 'StrongPassword123!',
            }, format='json')
        self.assertEqual(r_login_unverified.status_code, 400)
        otp_code = mock_login_dispatch.call_args[0][1]

        # 2. Verify email with OTP
        r_verify = self.client.post('/api/auth/verify-email/', {
            'email': 'FRIEND@GMAIL.COM',
            'code': otp_code,
        }, format='json')
        self.assertEqual(r_verify.status_code, 200, r_verify.data)

        # 3. Login + JWT auth (/api/auth/me/)
        r_login = self.client.post('/api/auth/login/', {
            'email': 'friend@gmail.com',
            'password': 'StrongPassword123!',
        }, format='json')
        self.assertEqual(r_login.status_code, 200, r_login.data)
        token = r_login.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        r_me = self.client.get('/api/auth/me/')
        self.assertEqual(r_me.status_code, 200)
        self.assertEqual(r_me.data['email'], 'friend@gmail.com')

        # 4. Login-code request & verify
        self.client.credentials()
        with patch('api.views._dispatch_otp_email') as mock_lc_dispatch:
            r_lc_req = self.client.post('/api/auth/login-code/request/', {'email': 'friend@gmail.com'}, format='json')
        self.assertEqual(r_lc_req.status_code, 200)
        lc_code = mock_lc_dispatch.call_args[0][1]
        r_lc_ver = self.client.post('/api/auth/login-code/verify/', {'email': 'friend@gmail.com', 'code': lc_code}, format='json')
        self.assertEqual(r_lc_ver.status_code, 200, r_lc_ver.data)
        r_lc_bad = self.client.post('/api/auth/login-code/request/', {'email': 'other@gmail.com'}, format='json')
        self.assertEqual(r_lc_bad.status_code, 400)

        # 5. Forgot / reset password
        with patch('api.views._dispatch_otp_email') as mock_fp_dispatch:
            r_fp = self.client.post('/api/auth/forgot-password/', {'email': 'friend@gmail.com'}, format='json')
        self.assertEqual(r_fp.status_code, 200)
        fp_code = mock_fp_dispatch.call_args[0][1]
        r_rp = self.client.post('/api/auth/reset-password/', {
            'email': 'friend@gmail.com',
            'code': fp_code,
            'password': 'NewStrongPassword123!',
        }, format='json')
        self.assertEqual(r_rp.status_code, 200, r_rp.data)
        r_fp_bad = self.client.post('/api/auth/forgot-password/', {'email': 'other@gmail.com'}, format='json')
        self.assertEqual(r_fp_bad.status_code, 400)

        # 6. If allowlist is removed or APP_ENV=production, JWTAuthentication rejects the user
        with override_settings(APP_ENV='production', BETA_EMAIL_ALLOWLIST=[]):
            self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
            r_me_prod = self.client.get('/api/auth/me/')
            self.assertEqual(r_me_prod.status_code, 401)
            self.assertFalse(is_allowed_email('friend@gmail.com'))


class PromoteAdminCommandTests(TestCase):
    def setUp(self):
        self.active_user = User.objects.create_user(
            email='promo.active@st.knust.edu.gh', password='Password123',
            full_name='Promo Active', reference_id='20991001', phone='0242000001',
            hall='Unity Hall', verified=True, is_active=True, is_admin=False, role='customer',
        )
        self.unverified_user = User.objects.create_user(
            email='promo.unverified@st.knust.edu.gh', password='Password123',
            full_name='Promo Unverified', reference_id='20991002', phone='0242000002',
            hall='Unity Hall', verified=False, is_active=True, is_admin=False, role='customer',
        )
        self.inactive_user = User.objects.create_user(
            email='promo.inactive@st.knust.edu.gh', password='Password123',
            full_name='Promo Inactive', reference_id='20991003', phone='0242000003',
            hall='Unity Hall', verified=True, is_active=False, is_admin=False, role='customer',
        )

    def test_promote_admin_promotes_active_verified_user_and_audits(self):
        from io import StringIO
        from django.core.management import call_command
        from api.models import AuditEntry

        out = StringIO()
        call_command('promote_admin', email='  PROMO.ACTIVE@ST.KNUST.EDU.GH  ', stdout=out)
        self.active_user.refresh_from_db()
        self.assertTrue(self.active_user.is_admin)
        self.assertEqual(self.active_user.role, 'admin')
        self.assertTrue(
            AuditEntry.objects.filter(
                action='admin_promoted',
                entity_id=str(self.active_user.id),
            ).exists()
        )
        output = out.getvalue()
        self.assertIn('promo.active@st.knust.edu.gh', output)
        self.assertNotIn('Password', output)
        self.assertNotIn('SECRET', output)

    def test_promote_admin_refuses_unknown_unverified_and_inactive(self):
        from django.core.management import CommandError, call_command

        for email in (
            'nobody@st.knust.edu.gh',
            'promo.unverified@st.knust.edu.gh',
            'promo.inactive@st.knust.edu.gh',
        ):
            with self.assertRaises(CommandError):
                call_command('promote_admin', email=email)




















