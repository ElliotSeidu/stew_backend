"""
Security regression tests for STEW API.

Each test class demonstrates a vulnerability/loophole before remediation and
stays as a regression guard after the fix.
"""
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import User, Vendor, Meal, Order, PayoutBatch, Review, SupportCase
from api.security import generate_jwt_token, _RATE_LIMIT_CACHE


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
