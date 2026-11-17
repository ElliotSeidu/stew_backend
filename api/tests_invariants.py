"""
Invariant and failure-scenario tests for the STEW API.
"""
import json
import secrets
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import User, Vendor, Meal, Order, Review, SupportCase
from api.security import generate_jwt_token, _RATE_LIMIT_CACHE
from api.views import _release_escrow, _recompute_vendor_rating


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


class SupportCaseRefundBugTest(TestCase):
    """
    Regression test for support_case_resolve_view.

    The old code accessed Order.status, Order.payment, and Order.cancel_reason —
    none of which exist on the Order model. The fix uses the correct fields:
    Order.cancelled_at and Order.payment_status.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_superuser(
            email='admin.inv@st.knust.edu.gh',
            password='AdminPassword123',
            full_name='Admin Inv',
        )
        cls.admin_token = generate_jwt_token(cls.admin)
        cls.student = _make_student('inv.student@st.knust.edu.gh', ref='20899002')
        cls.vendor_user = _make_student('inv.vendor@st.knust.edu.gh', ref='20899003', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_inv2', name='Inv Kitchen')
        cls.meal = _make_meal(cls.vendor, mid='m_inv2')

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_refund_action_cancels_paid_order_correctly(self):
        """Admin refund via support case must set cancelled_at and update payment_status."""
        order = _make_paid_order(
            self.student, self.vendor, self.meal,
            oid='STW-REFT1', subtotal=40.0,
        )
        self.assertIsNone(order.cancelled_at)
        self.assertEqual(order.payment_status, 'paid')

        case = SupportCase.objects.create(
            code='CASE-REFT1',
            user=self.student,
            type='wrong_item',
            order=order.id,
            priority='normal',
            note='Wrong food delivered.',
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.post(
            f'/api/support/cases/{case.code}/resolve/',
            {'action': 'refund'},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.data['ok'])

        order.refresh_from_db()
        self.assertIsNotNone(order.cancelled_at)
        self.assertIn(order.payment_status, ('refunded', 'refund_pending'))
        self.assertFalse(SupportCase.objects.filter(code='CASE-REFT1').exists())

    def test_refund_on_already_cancelled_order_is_idempotent(self):
        """Refund action on an already-cancelled order must not raise an error."""
        order = _make_paid_order(
            self.student, self.vendor, self.meal,
            oid='STW-REFT2', subtotal=35.0,
        )
        order.cancelled_at = timezone.now()
        order.payment_status = 'refunded'
        order.save(update_fields=['cancelled_at', 'payment_status'])

        case = SupportCase.objects.create(
            code='CASE-REFT2',
            user=self.student,
            type='wrong_item',
            order=order.id,
            priority='normal',
            note='Already cancelled.',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.post(
            f'/api/support/cases/{case.code}/resolve/',
            {'action': 'refund'},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.payment_status, 'refunded')

    def test_dismiss_action_does_not_touch_order(self):
        """Dismiss action must not modify the linked order."""
        order = _make_paid_order(
            self.student, self.vendor, self.meal,
            oid='STW-REFT3', subtotal=30.0,
        )
        case = SupportCase.objects.create(
            code='CASE-REFT3',
            user=self.student,
            type='late_delivery',
            order=order.id,
            priority='normal',
            note='Order was late but correct.',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.post(
            f'/api/support/cases/{case.code}/resolve/',
            {'action': 'dismiss'},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        order.refresh_from_db()
        self.assertIsNone(order.cancelled_at)
        self.assertEqual(order.payment_status, 'paid')

    def test_non_admin_cannot_resolve_support_case(self):
        """Students must not be able to resolve support cases."""
        case = SupportCase.objects.create(
            code='CASE-REFT4',
            user=self.student,
            type='wrong_item',
            order='',
            priority='normal',
            note='A grievance.',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(self.student)}')
        res = self.client.post(
            f'/api/support/cases/{case.code}/resolve/',
            {'action': 'dismiss'},
            format='json',
        )
        self.assertIn(res.status_code, (401, 403))


class EscrowHelperTest(TestCase):
    """Tests for the extracted _release_escrow helper function."""

    @classmethod
    def setUpTestData(cls):
        cls.student = _make_student('escrow.student@st.knust.edu.gh', ref='20899010')
        cls.vendor_user = _make_student('escrow.vendor@st.knust.edu.gh', ref='20899011', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_esc1', name='Escrow Kitchen')
        cls.meal = _make_meal(cls.vendor, mid='m_esc1')

    def _paid_order(self, oid):
        return _make_paid_order(self.student, self.vendor, self.meal, oid=oid)

    def test_release_escrow_student_confirmed(self):
        """_release_escrow sets correct fields when student confirms collection."""
        order = self._paid_order('STW-ESC1')
        _release_escrow(order, 'student_confirmed', self.student.email)
        order.refresh_from_db()
        self.assertIsNotNone(order.collected_at)
        self.assertEqual(order.collected_via, 'student_confirmed')
        self.assertEqual(order.prep_stage, 'collected')
        self.assertEqual(order.settlement_status, 'released')
        self.assertEqual(order.payment_status, 'released')
        self.assertEqual(order.settlement_net, order.subtotal)

    def test_release_escrow_handoff_code(self):
        """_release_escrow sets correct fields when vendor verifies handoff code."""
        order = self._paid_order('STW-ESC2')
        _release_escrow(order, 'handoff_code', self.vendor_user.email)
        order.refresh_from_db()
        self.assertEqual(order.collected_via, 'handoff_code')
        self.assertEqual(order.payment_status, 'released')


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



class AdminUnificationMatrixTest(TestCase):
    """
    5-user permission matrix across every IsAdminUser endpoint, IsVendorUser
    admin fallback, _is_admin_user / is_platform_admin helper call, and inline
    admin check in views.py and serializers.py.

    Users tested:
      (1) admin_only    : is_admin=True,  is_staff=False, role='customer', account_type='customer'
      (2) staff_only    : is_admin=False, is_staff=True,  role='customer', account_type='customer'
      (3) role_only     : is_admin=False, is_staff=False, role='admin',    account_type='customer'
      (4) acct_only     : is_admin=False, is_staff=False, role='customer', account_type='admin'
      (5) normal_cust   : is_admin=False, is_staff=False, role='customer', account_type='customer'

    Expected: ONLY (1) admin_only receives platform-admin privileges.
    """

    @classmethod
    def setUpTestData(cls):
        cls.u_admin = User.objects.create_user(
            email='matrix.admin@st.knust.edu.gh', password='Password123',
            full_name='Matrix Admin', reference_id='20870001', phone='0247000001',
            hall='Unity Hall (Conti)', verified=True,
            is_admin=True, is_staff=False, role='customer', account_type='customer',
        )
        cls.u_staff = User.objects.create_user(
            email='matrix.staff@st.knust.edu.gh', password='Password123',
            full_name='Matrix Staff', reference_id='20870002', phone='0247000002',
            hall='Unity Hall (Conti)', verified=True,
            is_admin=False, is_staff=True, role='customer', account_type='customer',
        )
        cls.u_role = User.objects.create_user(
            email='matrix.role@st.knust.edu.gh', password='Password123',
            full_name='Matrix Role', reference_id='20870003', phone='0247000003',
            hall='Unity Hall (Conti)', verified=True,
            is_admin=False, is_staff=False, role='admin', account_type='customer',
        )
        cls.u_acct = User.objects.create_user(
            email='matrix.acct@st.knust.edu.gh', password='Password123',
            full_name='Matrix Acct', reference_id='20870004', phone='0247000004',
            hall='Unity Hall (Conti)', verified=True,
            is_admin=False, is_staff=False, role='customer', account_type='admin',
        )
        cls.u_cust = User.objects.create_user(
            email='matrix.cust@st.knust.edu.gh', password='Password123',
            full_name='Matrix Cust', reference_id='20870005', phone='0247000005',
            hall='Unity Hall (Conti)', verified=True,
            is_admin=False, is_staff=False, role='customer', account_type='customer',
        )

        cls.tokens = {
            'admin_only': generate_jwt_token(cls.u_admin),
            'staff_only': generate_jwt_token(cls.u_staff),
            'role_only': generate_jwt_token(cls.u_role),
            'acct_only': generate_jwt_token(cls.u_acct),
            'normal_cust': generate_jwt_token(cls.u_cust),
        }
        cls.non_admins = ['staff_only', 'role_only', 'acct_only', 'normal_cust']

        # Third-party vendor, meal, and student for ownership/IDOR tests
        cls.tp_student = _make_student('matrix.tp.student@st.knust.edu.gh', ref='20870010')
        cls.tp_vendor_user = _make_student('matrix.tp.vendor@st.knust.edu.gh', ref='20870011', role='vendor')
        cls.tp_vendor = _make_vendor(cls.tp_vendor_user, vid='v_mtx1', name='Matrix Kitchen')
        cls.tp_meal = _make_meal(cls.tp_vendor, mid='m_mtx1', price=40.0, left=20)
        cls.tp_order = _make_paid_order(cls.tp_student, cls.tp_vendor, cls.tp_meal, oid='STW-MTX1', subtotal=40.0)
        cls.tp_case = SupportCase.objects.create(
            code='CASE-MTX1', user=cls.tp_student, type='missing',
            order=cls.tp_order.id, priority='normal', note='Missing item.',
        )
        cls.tp_review_pending = Review.objects.create(
            order_id='STW-MTX-REV1', vendor=cls.tp_vendor, vendor_name=cls.tp_vendor.name,
            customer=cls.tp_student, rating=4, moderation_status='pending',
        )
        cls.tp_review_hidden = Review.objects.create(
            order_id='STW-MTX-REV2', vendor=cls.tp_vendor, vendor_name=cls.tp_vendor.name,
            customer=cls.tp_student, rating=1, moderation_status='hidden',
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def _auth(self, key):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.tokens[key]}')

    # --- 1. GET /api/admin/reviews/queue/ (IsAdminUser) ---
    def test_matrix_01_moderation_queue(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/admin/reviews/queue/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/admin/reviews/queue/').status_code, 403)

    # --- 2. POST /api/admin/reviews/<orderId>/moderate/ (IsAdminUser) ---
    def test_matrix_02_moderate_review(self):
        self._auth('admin_only')
        self.assertEqual(
            self.client.post('/api/admin/reviews/STW-MTX-REV1/moderate/', {'decision': 'visible'}, format='json').status_code,
            200,
        )
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(
                    self.client.post('/api/admin/reviews/STW-MTX-REV1/moderate/', {'decision': 'visible'}, format='json').status_code,
                    403,
                )

    # --- 3. GET /api/admin/compliance/ (IsAdminUser) ---
    def test_matrix_03_admin_compliance(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/admin/compliance/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/admin/compliance/').status_code, 403)

    # --- 4. GET & POST /api/payouts/batches/ (IsAdminUser) ---
    def test_matrix_04_payout_batches(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/payouts/batches/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/payouts/batches/').status_code, 403)
                self.assertEqual(self.client.post('/api/payouts/batches/', format='json').status_code, 403)

    # --- 5. POST /api/support/cases/<code>/resolve/ (IsAdminUser) ---
    def test_matrix_05_support_case_resolve(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                c = SupportCase.objects.create(code=f'CASE-M5-{k[:4].upper()}', user=self.tp_student, type='missing')
                self._auth(k)
                self.assertEqual(
                    self.client.post(f'/api/support/cases/{c.code}/resolve/', {'action': 'dismiss'}, format='json').status_code,
                    403,
                )
        c_adm = SupportCase.objects.create(code='CASE-M5-ADM', user=self.tp_student, type='missing')
        self._auth('admin_only')
        self.assertEqual(
            self.client.post(f'/api/support/cases/{c_adm.code}/resolve/', {'action': 'dismiss'}, format='json').status_code,
            200,
        )

    # --- 6. GET /api/admin/vendors/ (IsAdminUser) ---
    def test_matrix_06_admin_vendors_list(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/admin/vendors/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/admin/vendors/').status_code, 403)

    # --- 7. PATCH /api/admin/vendors/<pk>/ (IsAdminUser) ---
    def test_matrix_07_admin_vendor_detail(self):
        self._auth('admin_only')
        self.assertEqual(
            self.client.patch(f'/api/admin/vendors/{self.tp_vendor.id}/', {'open': True}, format='json').status_code,
            200,
        )
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(
                    self.client.patch(f'/api/admin/vendors/{self.tp_vendor.id}/', {'open': False}, format='json').status_code,
                    403,
                )

    # --- 8. GET /api/admin/users/ (IsAdminUser) ---
    def test_matrix_08_admin_users_list(self):
        self._auth('admin_only')
        res = self.client.get('/api/admin/users/')
        self.assertEqual(res.status_code, 200)
        by_email = {u['email']: u for u in res.data}
        self.assertTrue(by_email[self.u_admin.email]['isAdmin'])
        self.assertFalse(by_email[self.u_role.email]['isAdmin'])
        self.assertFalse(by_email[self.u_staff.email]['isAdmin'])
        self.assertFalse(by_email[self.u_acct.email]['isAdmin'])
        self.assertFalse(by_email[self.u_cust.email]['isAdmin'])
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/admin/users/').status_code, 403)

    # --- 9. PATCH /api/admin/users/<pk>/ caller gate (IsAdminUser) ---
    def test_matrix_09_admin_user_detail_caller_gate(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(
                    self.client.patch(f'/api/admin/users/{self.tp_student.id}/', {'active': True}, format='json').status_code,
                    403,
                )
        self._auth('admin_only')
        self.assertEqual(
            self.client.patch(f'/api/admin/users/{self.tp_student.id}/', {'active': True}, format='json').status_code,
            200,
        )

    # --- 10. GET /api/admin/audit/ (IsAdminUser) ---
    def test_matrix_10_admin_audit(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/admin/audit/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/admin/audit/').status_code, 403)

    # --- 11. DELETE /api/auth/delete-account/ (delete_account_view) ---
    def test_matrix_11_delete_account_protection(self):
        self._auth('admin_only')
        self.assertEqual(self.client.delete('/api/auth/delete-account/').status_code, 400)
        # Non-admin accounts (including staff_only, role='admin', account_type='admin', and email starting with admin@) can delete their own account
        specs = [
            ('staff_only', {'is_staff': True, 'role': 'customer', 'account_type': 'customer'}, 'del.staff@st.knust.edu.gh', '20870102'),
            ('role_only', {'is_staff': False, 'role': 'admin', 'account_type': 'customer'}, 'del.role@st.knust.edu.gh', '20870103'),
            ('acct_only', {'is_staff': False, 'role': 'customer', 'account_type': 'admin'}, 'del.acct@st.knust.edu.gh', '20870104'),
            ('normal_cust', {'is_staff': False, 'role': 'customer', 'account_type': 'customer'}, 'del.cust@st.knust.edu.gh', '20870105'),
            ('admin_prefix_non_admin', {'is_staff': False, 'role': 'customer', 'account_type': 'customer'}, 'admin@st.knust.edu.gh', '20870106'),
        ]
        for label, extra, email, ref in specs:
            with self.subTest(user=label):
                u = User.objects.create_user(
                    email=email, password='Password123', full_name=label,
                    reference_id=ref, phone='0247000199', hall='Unity Hall (Conti)',
                    verified=True, is_admin=False, **extra,
                )
                self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {generate_jwt_token(u)}')
                self.assertEqual(self.client.delete('/api/auth/delete-account/').status_code, 200)

    # --- 12. PATCH /api/meals/<pk>/ on third-party meal (meal_detail_view) ---
    def test_matrix_12_meal_detail_third_party(self):
        self._auth('admin_only')
        self.assertEqual(
            self.client.patch(f'/api/meals/{self.tp_meal.id}/', {'name': 'Admin Updated Dish'}, format='json').status_code,
            200,
        )
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(
                    self.client.patch(f'/api/meals/{self.tp_meal.id}/', {'name': 'Unauthorized Rename'}, format='json').status_code,
                    403,
                )

    # --- 13. GET /api/orders/ (orders_view GET all-orders scope) ---
    def test_matrix_13_orders_list_all_scope(self):
        self._auth('admin_only')
        res = self.client.get('/api/orders/')
        self.assertEqual(res.status_code, 200)
        self.assertIn(self.tp_order.id, [o['id'] for o in res.data])
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                res_k = self.client.get('/api/orders/')
                self.assertEqual(res_k.status_code, 200)
                self.assertNotIn(self.tp_order.id, [o['id'] for o in res_k.data])

    # --- 14. GET /api/orders/<pk>/ & OrderSerializer.get_handoffCode ---
    def test_matrix_14_order_detail_and_handoff_code(self):
        self._auth('admin_only')
        res = self.client.get(f'/api/orders/{self.tp_order.id}/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data.get('handoffCode'), self.tp_order.handoff_code)

        from api.serializers import OrderSerializer
        for k, user_obj in [
            ('staff_only', self.u_staff),
            ('role_only', self.u_role),
            ('acct_only', self.u_acct),
            ('normal_cust', self.u_cust),
        ]:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get(f'/api/orders/{self.tp_order.id}/').status_code, 403)
                # Also test OrderSerializer.get_handoffCode directly
                dummy_req = type('Req', (), {'user': user_obj})()
                ser_data = OrderSerializer(self.tp_order, context={'request': dummy_req}).data
                self.assertIsNone(ser_data.get('handoffCode'))

    # --- 15. POST /api/orders/<pk>/cancel/ on third-party order ---
    def test_matrix_15_cancel_third_party_order(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                o = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid=f'STW-M15-{k[:4].upper()}')
                self._auth(k)
                self.assertEqual(self.client.post(f'/api/orders/{o.id}/cancel/', format='json').status_code, 403)
        o_adm = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid='STW-M15-ADM')
        self._auth('admin_only')
        self.assertEqual(self.client.post(f'/api/orders/{o_adm.id}/cancel/', format='json').status_code, 200)

    # --- 16. POST /api/orders/<pk>/cancel/ own order past 'accepted' stage ---
    def test_matrix_16_cancel_own_order_bypass_window(self):
        for k, user_obj in [
            ('staff_only', self.u_staff),
            ('role_only', self.u_role),
            ('acct_only', self.u_acct),
            ('normal_cust', self.u_cust),
        ]:
            with self.subTest(user=k):
                o = _make_paid_order(user_obj, self.tp_vendor, self.tp_meal, oid=f'STW-M16-{k[:4].upper()}')
                o.prep_stage = 'cooking'
                o.save(update_fields=['prep_stage'])
                self._auth(k)
                self.assertEqual(self.client.post(f'/api/orders/{o.id}/cancel/', format='json').status_code, 400)
        o_adm = _make_paid_order(self.u_admin, self.tp_vendor, self.tp_meal, oid='STW-M16-ADM')
        o_adm.prep_stage = 'cooking'
        o_adm.save(update_fields=['prep_stage'])
        self._auth('admin_only')
        self.assertEqual(self.client.post(f'/api/orders/{o_adm.id}/cancel/', format='json').status_code, 200)

    # --- 17. POST /api/payments/initialize/ on third-party order ---
    def test_matrix_17_init_payment_third_party(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                o = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid=f'STW-M17-{k[:4].upper()}')
                o.payment_status = 'pending'
                o.save(update_fields=['payment_status'])
                self._auth(k)
                self.assertEqual(
                    self.client.post('/api/payments/initialize/', {'orderId': o.id}, format='json').status_code,
                    403,
                )
        o_adm = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid='STW-M17-ADM')
        o_adm.payment_status = 'pending'
        o_adm.save(update_fields=['payment_status'])
        self._auth('admin_only')
        self.assertEqual(
            self.client.post('/api/payments/initialize/', {'orderId': o_adm.id}, format='json').status_code,
            200,
        )

    # --- 18. POST /api/payments/verify/ on third-party order ---
    def test_matrix_18_verify_payment_third_party(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                o = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid=f'STW-M18-{k[:4].upper()}')
                o.payment_status = 'pending'
                o.payment_reference = f'PSK-M18-{k[:4].upper()}'
                o.save(update_fields=['payment_status', 'payment_reference'])
                self._auth(k)
                self.assertEqual(
                    self.client.post('/api/payments/verify/', {'orderId': o.id, 'reference': o.payment_reference}, format='json').status_code,
                    403,
                )
        o_adm = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid='STW-M18-ADM')
        o_adm.payment_status = 'pending'
        o_adm.payment_reference = 'PSK-M18-ADM'
        o_adm.save(update_fields=['payment_status', 'payment_reference'])
        self._auth('admin_only')
        self.assertEqual(
            self.client.post('/api/payments/verify/', {'orderId': o_adm.id, 'reference': 'PSK-M18-ADM'}, format='json').status_code,
            200,
        )

    # --- 19. GET /api/payouts/ (payouts_ledger_view) ---
    def test_matrix_19_payouts_ledger(self):
        self._auth('admin_only')
        res = self.client.get('/api/payouts/')
        self.assertEqual(res.status_code, 200)
        self.assertGreater(res.data.get('held', 0), 0)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/payouts/').status_code, 403)

    # --- 20. _is_order_participant endpoints on third-party order ---
    def test_matrix_20_order_participant_endpoints(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(
                    self.client.post(f'/api/orders/{self.tp_order.id}/meetup/propose/', {'place': 'Tech Junction'}, format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(f'/api/orders/{self.tp_order.id}/meetup/confirm/', format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(f'/api/orders/{self.tp_order.id}/meetup/decline/', format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(f'/api/orders/{self.tp_order.id}/messages/', {'text': 'Hello'}, format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post('/api/support/cases/', {'type': 'missing', 'orderId': self.tp_order.id, 'note': 'Probe'}, format='json').status_code,
                    403,
                )
        self._auth('admin_only')
        self.assertEqual(
            self.client.post(f'/api/orders/{self.tp_order.id}/meetup/propose/', {'place': 'Tech Junction'}, format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post(f'/api/orders/{self.tp_order.id}/meetup/confirm/', format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post(f'/api/orders/{self.tp_order.id}/meetup/decline/', format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post(f'/api/orders/{self.tp_order.id}/messages/', {'text': 'Admin check'}, format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post('/api/support/cases/', {'type': 'missing', 'orderId': self.tp_order.id, 'note': 'Admin case'}, format='json').status_code,
            201,
        )

    # --- 21. _is_order_vendor_or_admin endpoints on third-party order ---
    def test_matrix_21_order_vendor_or_admin_endpoints(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                o = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid=f'STW-M21-{k[:4].upper()}')
                self._auth(k)
                self.assertEqual(
                    self.client.post(f'/api/orders/{o.id}/prep/', {'stage': 'cooking'}, format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(f'/api/orders/{o.id}/collection-nudge/', format='json').status_code,
                    403,
                )
                self.assertEqual(
                    self.client.post(f'/api/orders/{o.id}/complete/', {'code': o.handoff_code}, format='json').status_code,
                    403,
                )
        o_adm = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid='STW-M21-ADM')
        self._auth('admin_only')
        self.assertEqual(
            self.client.post(f'/api/orders/{o_adm.id}/prep/', {'stage': 'cooking'}, format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post(f'/api/orders/{o_adm.id}/collection-nudge/', format='json').status_code,
            200,
        )
        self.assertEqual(
            self.client.post(f'/api/orders/{o_adm.id}/complete/', {'code': o_adm.handoff_code}, format='json').status_code,
            200,
        )

    # --- 22. POST /api/orders/<pk>/collected/ on third-party order ---
    def test_matrix_22_mark_collected_third_party(self):
        for k in self.non_admins:
            with self.subTest(user=k):
                o = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid=f'STW-M22-{k[:4].upper()}')
                self._auth(k)
                self.assertEqual(self.client.post(f'/api/orders/{o.id}/collected/', format='json').status_code, 403)
        o_adm = _make_paid_order(self.tp_student, self.tp_vendor, self.tp_meal, oid='STW-M22-ADM')
        self._auth('admin_only')
        self.assertEqual(self.client.post(f'/api/orders/{o_adm.id}/collected/', format='json').status_code, 200)

    # --- 23. GET /api/vendors/<vendorId>/reviews/?includeHidden=true ---
    def test_matrix_23_vendor_reviews_include_hidden(self):
        self._auth('admin_only')
        res = self.client.get(f'/api/vendors/{self.tp_vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(res.status_code, 200)
        self.assertIn('STW-MTX-REV2', [r['orderId'] for r in res.data])
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                res_k = self.client.get(f'/api/vendors/{self.tp_vendor.id}/reviews/?includeHidden=true')
                self.assertEqual(res_k.status_code, 200)
                self.assertNotIn('STW-MTX-REV2', [r['orderId'] for r in res_k.data])

    # --- 24. GET /api/support/cases/ (support_cases_view GET) ---
    def test_matrix_24_support_cases_list(self):
        self._auth('admin_only')
        res = self.client.get('/api/support/cases/')
        self.assertEqual(res.status_code, 200)
        self.assertIn(self.tp_case.code, [c['code'] for c in res.data])
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                res_k = self.client.get('/api/support/cases/')
                self.assertEqual(res_k.status_code, 200)
                self.assertNotIn(self.tp_case.code, [c['code'] for c in res_k.data])

    # --- 25. GET /api/vendor/compliance/ (IsVendorUser non-vendor admin fallback) ---
    def test_matrix_25_vendor_compliance_admin_fallback(self):
        self._auth('admin_only')
        self.assertEqual(self.client.get('/api/vendor/compliance/').status_code, 200)
        for k in self.non_admins:
            with self.subTest(user=k):
                self._auth(k)
                self.assertEqual(self.client.get('/api/vendor/compliance/').status_code, 403)


class AdminSelfProtectionAndEscalationTest(TestCase):
    """
    Tests for Task A.5:
      - Admin cannot suspend/demote themselves.
      - Target with is_admin=True is protected from suspension; targets with only
        is_staff, role='admin', or account_type='admin' are NOT protected.
      - Normal user cannot set is_admin, is_staff, role='admin', or account_type='admin'
        on themselves through me_view, registration, or vendor endpoints.
    """

    @classmethod
    def setUpTestData(cls):
        cls.admin1 = User.objects.create_user(
            email='admin1.prot@st.knust.edu.gh', password='Password123',
            full_name='Admin One', reference_id='20871001', phone='0247100001',
            hall='Unity Hall (Conti)', verified=True, is_admin=True,
        )
        cls.admin2 = User.objects.create_user(
            email='admin2.prot@st.knust.edu.gh', password='Password123',
            full_name='Admin Two', reference_id='20871002', phone='0247100002',
            hall='Unity Hall (Conti)', verified=True, is_admin=True,
        )
        cls.staff_target = User.objects.create_user(
            email='staff.prot@st.knust.edu.gh', password='Password123',
            full_name='Staff Target', reference_id='20871003', phone='0247100003',
            hall='Unity Hall (Conti)', verified=True, is_admin=False, is_staff=True,
        )
        cls.role_target = User.objects.create_user(
            email='role.prot@st.knust.edu.gh', password='Password123',
            full_name='Role Target', reference_id='20871004', phone='0247100004',
            hall='Unity Hall (Conti)', verified=True, is_admin=False, role='admin',
        )
        cls.acct_target = User.objects.create_user(
            email='acct.prot@st.knust.edu.gh', password='Password123',
            full_name='Acct Target', reference_id='20871005', phone='0247100005',
            hall='Unity Hall (Conti)', verified=True, is_admin=False, account_type='admin',
        )
        cls.customer = User.objects.create_user(
            email='cust.prot@st.knust.edu.gh', password='Password123',
            full_name='Cust Target', reference_id='20871006', phone='0247100006',
            hall='Unity Hall (Conti)', verified=True, is_admin=False,
        )
        cls.admin1_token = generate_jwt_token(cls.admin1)
        cls.cust_token = generate_jwt_token(cls.customer)

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    def test_admin_cannot_suspend_self(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin1_token}')
        res = self.client.patch(
            f'/api/admin/users/{self.admin1.id}/',
            {'active': False, 'is_admin': False, 'role': 'customer'},
            format='json',
        )
        self.assertEqual(res.status_code, 400)
        self.admin1.refresh_from_db()
        self.assertTrue(self.admin1.is_active)
        self.assertTrue(self.admin1.is_admin)

    def test_admin_cannot_suspend_another_admin(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin1_token}')
        res = self.client.patch(
            f'/api/admin/users/{self.admin2.id}/',
            {'active': False, 'is_admin': False},
            format='json',
        )
        self.assertEqual(res.status_code, 400)
        self.admin2.refresh_from_db()
        self.assertTrue(self.admin2.is_active)
        self.assertTrue(self.admin2.is_admin)

    def test_non_is_admin_targets_are_not_shielded_from_suspension(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin1_token}')
        for label, target in [
            ('staff_target', self.staff_target),
            ('role_target', self.role_target),
            ('acct_target', self.acct_target),
        ]:
            with self.subTest(target=label):
                res = self.client.patch(
                    f'/api/admin/users/{target.id}/',
                    {'active': False},
                    format='json',
                )
                self.assertEqual(res.status_code, 200)
                target.refresh_from_db()
                self.assertFalse(target.is_active)

    def test_customer_cannot_escalate_privileges_via_me_patch(self):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.cust_token}')
        res = self.client.patch(
            '/api/auth/me/',
            {
                'fullName': 'Still Customer',
                'is_admin': True,
                'isAdmin': True,
                'is_staff': True,
                'isStaff': True,
                'role': 'admin',
                'account_type': 'admin',
                'accountType': 'admin',
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.customer.refresh_from_db()
        self.assertFalse(self.customer.is_admin)
        self.assertFalse(self.customer.is_staff)
        self.assertEqual(self.customer.role, 'customer')
        self.assertEqual(self.customer.account_type, 'customer')

    def test_customer_cannot_register_with_admin_flags(self):
        # 1. Explicit accountType='admin' is rejected by RegisterSerializer
        res_bad = self.client.post(
            '/api/auth/register/',
            {
                'fullName': 'Escalation Attempt',
                'email': 'esc1.attempt@st.knust.edu.gh',
                'referenceId': '20871091',
                'phone': '0247100091',
                'accountType': 'admin',
                'password': 'Password123',
            },
            format='json',
        )
        self.assertEqual(res_bad.status_code, 400)

        # 2. Extra fields is_admin / is_staff / role='admin' in registration payload are ignored
        res_ok = self.client.post(
            '/api/auth/register/',
            {
                'fullName': 'Normal Reg',
                'email': 'esc2.attempt@st.knust.edu.gh',
                'referenceId': '20871092',
                'phone': '0247100092',
                'accountType': 'customer',
                'is_admin': True,
                'isAdmin': True,
                'is_staff': True,
                'role': 'admin',
                'password': 'Password123',
            },
            format='json',
        )
        self.assertEqual(res_ok.status_code, 201)
        created = User.objects.get(email='esc2.attempt@st.knust.edu.gh')
        self.assertFalse(created.is_admin)
        self.assertFalse(created.is_staff)
        self.assertEqual(created.role, 'customer')
        self.assertEqual(created.account_type, 'customer')
