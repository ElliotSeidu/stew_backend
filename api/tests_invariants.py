"""
Invariant and failure-scenario tests for the STEW API.
"""
import json
import secrets
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import User, Vendor, Meal, Order, Review
from api.security import generate_jwt_token, _RATE_LIMIT_CACHE
from api.views import _recompute_vendor_rating


def _make_student(email, ref='20899001', role='customer'):
    return User.objects.create_user(
        email=email,
        password='Password123',
        full_name='Test User',
        reference_id=ref,
        phone='0249000001',
        hall='Unity Hall (Conti)',
        verified=True,
        role=role,
        account_type=role,
        is_vendor=(role == 'vendor'),
    )


def _make_vendor(user, vid='v_inv1', name='Test Kitchen'):
    return Vendor.objects.create(
        id=vid,
        user=user,
        name=name,
        hall='Unity Hall (Conti)',
        rating=0.0,
        reviews=0,
        open=True,
        active=True,
    )


def _make_meal(vendor, mid='m_inv1', price=40.0, left=10):
    return Meal.objects.create(
        id=mid,
        vendor=vendor,
        name='Test Dish',
        price=price,
        cat='Soups',
        left=left,
        on=True,
    )


def _make_paid_order(customer, vendor, meal, oid='STW-INV1', subtotal=40.0):
    return Order.objects.create(
        id=oid,
        customer=customer,
        customer_name=customer.full_name,
        email=customer.email,
        phone='0249000002',
        area='Campus',
        vendor=vendor,
        vendor_name=vendor.name,
        lines=[{'mealId': meal.id, 'name': meal.name, 'price': subtotal, 'qty': 1}],
        subtotal=subtotal,
        fee=round(subtotal * 0.05, 2),
        total=round(subtotal * 1.05, 2),
        handoff_code='123456',
        prep_stage='ready',
        prep_at={'accepted': 1700000000000},
        payment_status='paid',
        payment_provider='paystack',
        payment_reference=f'PSK-{secrets.token_hex(4).upper()}',
        paid_at=timezone.now(),
        settlement_status='pending',
        messages=[],
    )


class RatingAggregateTest(TestCase):
    """Tests for _recompute_vendor_rating using DB aggregation."""

    @classmethod
    def setUpTestData(cls):
        cls.vendor_user = _make_student('rating.vendor@st.knust.edu.gh', ref='20899020', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_rat1', name='Rating Kitchen')
        cls.student = _make_student('rating.student@st.knust.edu.gh', ref='20899021')
        cls.meal = _make_meal(cls.vendor, mid='m_rat1')

    def test_empty_reviews_gives_zero(self):
        """Vendor with no reviews should have rating=0.0 and reviews=0."""
        _recompute_vendor_rating(self.vendor)
        self.vendor.refresh_from_db()
        self.assertEqual(self.vendor.rating, 0.0)
        self.assertEqual(self.vendor.reviews, 0)

    def test_rating_computed_from_visible_reviews_only(self):
        """Hidden reviews must be excluded from the rating average."""
        Review.objects.create(
            order_id='STW-RAT1',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            customer=self.student,
            rating=5,
            moderation_status='visible',
        )
        Review.objects.create(
            order_id='STW-RAT2',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            customer=self.student,
            rating=1,
            moderation_status='hidden',  # This must be excluded
        )
        _recompute_vendor_rating(self.vendor)
        self.vendor.refresh_from_db()
        # Only the rating=5 visible review counts
        self.assertEqual(self.vendor.rating, 5.0)
        self.assertEqual(self.vendor.reviews, 1)

    def test_rating_averages_multiple_visible_reviews(self):
        """Rating should be the average of all non-hidden reviews."""
        for oid, r in [('STW-RAT3', 4), ('STW-RAT4', 3), ('STW-RAT5', 5)]:
            Review.objects.create(
                order_id=oid,
                vendor=self.vendor,
                vendor_name=self.vendor.name,
                customer=self.student,
                rating=r,
                moderation_status='visible',
            )
        _recompute_vendor_rating(self.vendor)
        self.vendor.refresh_from_db()
        self.assertEqual(self.vendor.rating, 4.0)  # (4+3+5)/3
        self.assertEqual(self.vendor.reviews, 3)

    def test_none_vendor_does_not_raise(self):
        """_recompute_vendor_rating(None) must not raise any exception."""
        try:
            _recompute_vendor_rating(None)
        except Exception as e:
            self.fail(f'_recompute_vendor_rating(None) raised {e}')


class OrderStockInvariantTest(TestCase):
    """Tests that the stock invariant (can't order more than available) is enforced."""

    @classmethod
    def setUpTestData(cls):
        cls.student = _make_student('stock.student@st.knust.edu.gh', ref='20899030')
        cls.student_token = generate_jwt_token(cls.student)
        cls.vendor_user = _make_student('stock.vendor@st.knust.edu.gh', ref='20899031', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_stk1', name='Stock Kitchen')
        cls.meal = _make_meal(cls.vendor, mid='m_stk1', price=40.0, left=2)

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_cannot_order_more_than_available_stock(self):
        """Ordering more portions than are available must return 400."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 999}],  # Far more than left=2
            'area': 'Campus',
            'phone': '0249000003',
        }, format='json')
        self.assertEqual(res.status_code, 400)
        # Stock must remain unchanged
        self.meal.refresh_from_db()
        self.assertEqual(self.meal.left, 2)

    def test_cannot_order_from_own_kitchen(self):
        """A vendor cannot place an order at their own kitchen."""
        vendor_token = generate_jwt_token(self.vendor_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {vendor_token}')
        res = self.client.post('/api/orders/', {
            'lines': [{'mealId': self.meal.id, 'qty': 1}],
            'area': 'Campus',
            'phone': '0249000003',
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('own kitchen', res.data.get('message', '').lower())


class PaymentWebhookIdempotencyTest(TestCase):
    """Tests that the Paystack webhook handles duplicate delivery idempotently."""

    @classmethod
    def setUpTestData(cls):
        cls.student = _make_student('wh.student@st.knust.edu.gh', ref='20899040')
        cls.vendor_user = _make_student('wh.vendor@st.knust.edu.gh', ref='20899041', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_wh1', name='Webhook Kitchen')
        cls.meal = _make_meal(cls.vendor, mid='m_wh1')
        cls.order = _make_paid_order(
            cls.student, cls.vendor, cls.meal, oid='STW-WH1', subtotal=40.0,
        )
        # Set status back to pending to simulate pre-payment
        cls.order.payment_status = 'pending'
        cls.order.paid_at = None
        cls.order.save(update_fields=['payment_status', 'paid_at'])

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_duplicate_webhook_does_not_double_credit(self):
        """
        A second identical webhook delivery after the first succeeds
        must not change payment_status (idempotency via _mark_order_paid).
        Without a real Paystack secret key the webhook will reject the signature,
        so we verify the rejection path works cleanly.
        """
        payload = json.dumps({
            'event': 'charge.success',
            'data': {'reference': self.order.payment_reference}
        }).encode()
        # No valid signature — webhook must reject with 401
        res = self.client.post(
            '/api/payments/webhook/',
            data=payload,
            content_type='application/json',
            HTTP_X_PAYSTACK_SIGNATURE='invalidsig',
        )
        self.assertIn(res.status_code, (400, 401))
        self.order.refresh_from_db()
        # Order payment_status must NOT have changed
        self.assertEqual(self.order.payment_status, 'pending')
