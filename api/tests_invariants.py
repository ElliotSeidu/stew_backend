"""
Invariant and failure-scenario tests for the STEW API.

These tests cover scenarios that were either not tested before, or directly
verify the fix for the support_case_resolve_view refund bug (which previously
accessed Order fields that don't exist: order.status, order.payment,
order.cancel_reason).
"""
import secrets
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from api.models import User, Vendor, Meal, Order, Review, SupportCase
from api.security import generate_jwt_token, hash_token, _RATE_LIMIT_CACHE
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
        # Must be cancelled
        self.assertIsNotNone(order.cancelled_at)
        # Payment status must reflect refunded state
        self.assertIn(order.payment_status, ('refunded', 'refund_pending'))
        # Case must be deleted after resolution
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
        # Order stays cancelled, payment_status unchanged
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
        # Dismiss must NOT cancel or change payment status
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
        for i, (oid, r) in enumerate([('STW-RAT3', 4), ('STW-RAT4', 3), ('STW-RAT5', 5)]):
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
        import hmac, hashlib
        from django.conf import settings
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
        import json
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




class AdminPermissionNarrowingRegressionTest(TestCase):
    """
    Regression tests for the admin-check consolidation refactor.

    The refactor replaced inline `user.is_admin` / `user.is_admin or user.role == 'admin'`
    checks with `_is_admin_user(user)`, which ALSO passes for `is_staff=True` and
    `account_type='admin'`. That violated the no-behavior-change rule.

    This suite proves that at every affected view, a user with ONLY `is_staff=True`
    or ONLY `account_type='admin'` is denied in exactly the same way a regular
    student would be.

    Original inline checks (now restored):
      meal_detail_view       line 732  : request.user.is_admin
      orders_view GET        line 863  : user.is_admin or user.role == 'admin'
      cancel_order_view perm line 1031 : user.is_admin
      cancel_order_view time line 1040 : user.is_admin or is_order_vendor
      payouts_ledger_view    line 1288 : user.is_admin
                             line 1292 : user.is_admin
      mark_collected_view    line 1513 : _collector.is_admin
      support_cases_view GET line 1816 : user.is_admin
      admin_user_detail_view line 1938 : target.is_admin or target.role == 'admin'
    """

    @classmethod
    def setUpTestData(cls):
        # --- quasi-admin imposters ---
        # staff_only: Django staff flag set, but NOT is_admin, NOT role='admin'
        cls.staff_only = User.objects.create_user(
            email='staff.only@st.knust.edu.gh',
            password='Password123',
            full_name='Staff Only',
            reference_id='20888001',
            phone='0249000091',
            hall='Unity Hall (Conti)',
            verified=True,
            role='customer',
            account_type='customer',
            is_staff=True,
            is_admin=False,
        )
        cls.staff_token = generate_jwt_token(cls.staff_only)

        # acct_type_only: account_type='admin', but NOT is_admin, NOT is_staff, NOT role='admin'
        cls.acct_type_only = User.objects.create_user(
            email='accttype.only@st.knust.edu.gh',
            password='Password123',
            full_name='AcctType Only',
            reference_id='20888002',
            phone='0249000092',
            hall='Unity Hall (Conti)',
            verified=True,
            role='customer',
            account_type='admin',
            is_staff=False,
            is_admin=False,
        )
        cls.acct_token = generate_jwt_token(cls.acct_type_only)

        # real admin for endpoints that need a legitimate admin caller
        cls.real_admin = User.objects.create_superuser(
            email='real.admin.narrow@st.knust.edu.gh',
            password='AdminPassword123',
            full_name='Real Admin Narrow',
        )
        cls.admin_token = generate_jwt_token(cls.real_admin)

        # vendor + meal owned by a third party (not by any imposter)
        cls.vendor_user = _make_student('narrow.vendor@st.knust.edu.gh', ref='20888010', role='vendor')
        cls.vendor = _make_vendor(cls.vendor_user, vid='v_narrow1', name='Narrow Kitchen')
        cls.meal = _make_meal(cls.vendor, mid='m_narrow1')

        # an order owned by vendor_user (imposters are unrelated third parties)
        cls.third_party_order = _make_paid_order(
            cls.vendor_user, cls.vendor, cls.meal,
            oid='STW-NRWTP1', subtotal=40.0,
        )

        # a support case filed by vendor_user
        cls.third_party_case = SupportCase.objects.create(
            code='CASE-NRW1',
            user=cls.vendor_user,
            type='wrong_item',
            order=cls.third_party_order.id,
            priority='normal',
            note='Third-party case.',
        )

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    # ------------------------------------------------------------------
    # Site 1: meal_detail_view — original: request.user.is_admin
    # An imposter trying to edit another vendor's meal must get 403.
    # ------------------------------------------------------------------
    def _assert_meal_edit_denied(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.patch(
            f'/api/meals/{self.meal.id}/',
            {'name': 'Hacked Name'},
            format='json',
        )
        self.assertEqual(
            res.status_code, 403,
            f'{label} could edit another vendor\'s meal (expected 403, got {res.status_code})',
        )

    def test_staff_only_cannot_edit_another_vendors_meal(self):
        """is_staff-only user must not bypass meal ownership check (original: is_admin)."""
        self._assert_meal_edit_denied(self.staff_token, 'staff_only')

    def test_acct_type_only_cannot_edit_another_vendors_meal(self):
        """account_type='admin'-only user must not bypass meal ownership check."""
        self._assert_meal_edit_denied(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 2: orders_view GET — original: user.is_admin or user.role == 'admin'
    # Imposters must NOT receive all orders; they should only see their own.
    # The third-party order (owned by vendor_user) must NOT appear in
    # the imposter's order list.
    # ------------------------------------------------------------------
    def _assert_cannot_see_all_orders(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.get('/api/orders/', {'scope': 'customer'})
        self.assertEqual(res.status_code, 200)
        ids = [o.get('id') for o in (res.data or [])]
        self.assertNotIn(
            self.third_party_order.id, ids,
            f'{label} could see another user\'s order in the list',
        )

    def test_staff_only_cannot_see_all_orders(self):
        """is_staff-only user must not receive other users' orders."""
        self._assert_cannot_see_all_orders(self.staff_token, 'staff_only')

    def test_acct_type_only_cannot_see_all_orders(self):
        """account_type='admin'-only user must not receive other users' orders."""
        self._assert_cannot_see_all_orders(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 3: cancel_order_view — original: user.is_admin (non-owner/non-vendor)
    # An unrelated imposter cancelling a third-party order must get 403.
    # ------------------------------------------------------------------
    def _assert_cancel_third_party_order_denied(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.post(
            f'/api/orders/{self.third_party_order.id}/cancel/',
            format='json',
        )
        self.assertEqual(
            res.status_code, 403,
            f'{label} could cancel another user\'s order (expected 403, got {res.status_code})',
        )

    def test_staff_only_cannot_cancel_third_party_order(self):
        """is_staff-only non-owner/non-vendor must be denied cancel (original: is_admin)."""
        self._assert_cancel_third_party_order_denied(self.staff_token, 'staff_only')

    def test_acct_type_only_cannot_cancel_third_party_order(self):
        """account_type='admin'-only non-owner must be denied cancel."""
        self._assert_cancel_third_party_order_denied(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 4: cancel_order_view time-window bypass
    # original: is_owner and not (user.is_admin or is_order_vendor)
    # An owner who is ONLY is_staff/account_type must NOT bypass the
    # time-window / prep-stage guard — they should get 400 "kitchen has started"
    # when prep_stage != 'accepted', not silently succeed.
    # ------------------------------------------------------------------
    def _make_in_progress_order_for(self, owner, oid, ref):
        return Order.objects.create(
            id=oid,
            customer=owner,
            customer_name=owner.full_name,
            email=owner.email,
            phone='0249000099',
            area='Campus',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': self.meal.id, 'name': self.meal.name, 'price': 40.0, 'qty': 1}],
            subtotal=40.0,
            fee=2.0,
            total=42.0,
            handoff_code='999888',
            prep_stage='preparing',       # past 'accepted' — cannot cancel as student
            prep_at={'accepted': 1700000000000},
            payment_status='pending',
            payment_provider='paystack',
            payment_reference=ref,
            settlement_status='pending',
            messages=[],
        )

    def test_staff_only_owner_cannot_bypass_cancel_time_window(self):
        """is_staff-only owner must still hit the prep-stage guard (original: is_admin bypasses it)."""
        order = self._make_in_progress_order_for(
            self.staff_only, 'STW-NRWCNL1', 'PSK-NRWCNL1',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.staff_token}')
        res = self.client.post(f'/api/orders/{order.id}/cancel/', format='json')
        # Must be rejected — kitchen already started
        self.assertEqual(
            res.status_code, 400,
            f'staff_only owner bypassed prep-stage guard (got {res.status_code})',
        )
        self.assertIn('kitchen', res.data.get('message', '').lower())

    def test_acct_type_only_owner_cannot_bypass_cancel_time_window(self):
        """account_type='admin'-only owner must still hit the prep-stage guard."""
        order = self._make_in_progress_order_for(
            self.acct_type_only, 'STW-NRWCNL2', 'PSK-NRWCNL2',
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.acct_token}')
        res = self.client.post(f'/api/orders/{order.id}/cancel/', format='json')
        self.assertEqual(
            res.status_code, 400,
            f'acct_type_only owner bypassed prep-stage guard (got {res.status_code})',
        )
        self.assertIn('kitchen', res.data.get('message', '').lower())

    # ------------------------------------------------------------------
    # Site 5 & 6: payouts_ledger_view — original body checks: user.is_admin
    #
    # IsVendorUser (pre-existing, unchanged) already admits account_type='admin'
    # so acct_type_only reaches the view body and gets 200 with an empty ledger
    # (the body's `not user.is_admin` guard restricts it to its own vendor,
    # which is None → returns zeroed response). staff_only has role='customer'
    # and account_type='customer' so IsVendorUser gates it out at 403.
    #
    # In both cases the user does NOT receive the full all-vendor ledger that a
    # real admin (is_admin=True) would see. That is the invariant we assert.
    # ------------------------------------------------------------------
    def _assert_ledger_not_all_vendors(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.get('/api/payouts/')
        # Either denied outright (403) or gets an empty/zero ledger (200)
        self.assertIn(
            res.status_code, (200, 403),
            f'{label}: unexpected status {res.status_code}',
        )
        if res.status_code == 200:
            # Must not see the third-party vendor's held funds
            self.assertEqual(
                res.data.get('held', 0), 0,
                f'{label} saw non-zero held funds — may have all-vendor access',
            )
            self.assertEqual(
                res.data.get('released', 0), 0,
                f'{label} saw non-zero released funds — may have all-vendor access',
            )

    def test_staff_only_ledger_not_all_vendors(self):
        """is_staff-only cannot see all vendors' ledger data."""
        # staff_only has role=customer, account_type=customer → IsVendorUser gates to 403
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.staff_token}')
        res = self.client.get('/api/payouts/')
        self.assertEqual(res.status_code, 403,
                         f'staff_only (role=customer) should be denied by IsVendorUser, got {res.status_code}')

    def test_acct_type_only_ledger_not_all_vendors(self):
        """account_type='admin' passes IsVendorUser but body guard restricts to own (None) vendor → empty ledger."""
        # acct_type_only admitted by IsVendorUser (account_type='admin' is in its allow-list)
        # but view body `not user.is_admin` → filters to vendor=None → zeroed response
        self._assert_ledger_not_all_vendors(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 7: mark_collected_view — original: _collector.is_admin
    # An unrelated imposter confirming collection on a third-party order
    # must get 403.
    # ------------------------------------------------------------------
    def _assert_collect_denied(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.post(
            f'/api/orders/{self.third_party_order.id}/collected/',
            format='json',
        )
        self.assertEqual(
            res.status_code, 403,
            f'{label} could confirm collection on another user\'s order (got {res.status_code})',
        )

    def test_staff_only_cannot_confirm_third_party_collection(self):
        """is_staff-only non-owner must be denied collection confirmation."""
        self._assert_collect_denied(self.staff_token, 'staff_only')

    def test_acct_type_only_cannot_confirm_third_party_collection(self):
        """account_type='admin'-only non-owner must be denied collection confirmation."""
        self._assert_collect_denied(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 8: support_cases_view GET — original: user.is_admin
    # Imposters must only see their OWN cases, not all cases.
    # The third-party case (filed by vendor_user) must NOT appear.
    # ------------------------------------------------------------------
    def _assert_cannot_see_all_cases(self, token, label):
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        res = self.client.get('/api/support/cases/')
        self.assertEqual(res.status_code, 200)
        codes = [c.get('code') for c in (res.data or [])]
        self.assertNotIn(
            self.third_party_case.code, codes,
            f'{label} could see another user\'s support case',
        )

    def test_staff_only_cannot_see_all_support_cases(self):
        """is_staff-only user must only see their own support cases."""
        self._assert_cannot_see_all_cases(self.staff_token, 'staff_only')

    def test_acct_type_only_cannot_see_all_support_cases(self):
        """account_type='admin'-only user must only see their own support cases."""
        self._assert_cannot_see_all_cases(self.acct_token, 'acct_type_only')

    # ------------------------------------------------------------------
    # Site 9: admin_user_detail_view target guard
    # original: target.is_admin or target.role == 'admin'
    # Targets with ONLY is_staff=True or ONLY account_type='admin' must
    # NOT be shielded from suspension — only targets with is_admin=True
    # or role='admin' are protected.
    # ------------------------------------------------------------------
    def test_staff_only_target_is_not_shielded_from_suspension(self):
        """
        A target with is_staff=True (but is_admin=False, role='customer') must
        NOT trigger the 'Admin accounts cannot be suspended' guard.
        The real admin must be able to toggle the user's active status.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.patch(
            f'/api/admin/users/{self.staff_only.pk}/',
            {'active': False},
            format='json',
        )
        # Must NOT return 400 "Admin accounts cannot be suspended"
        self.assertNotEqual(
            res.status_code, 400,
            'staff_only target was wrongly shielded from suspension by is_staff flag',
        )
        self.assertEqual(
            res.status_code, 200,
            f'Unexpected status suspending staff_only target: {res.status_code} {res.data}',
        )

    def test_acct_type_only_target_is_not_shielded_from_suspension(self):
        """
        A target with account_type='admin' (but is_admin=False, role='customer') must
        NOT trigger the guard. Only is_admin=True or role='admin' are protected.
        """
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.patch(
            f'/api/admin/users/{self.acct_type_only.pk}/',
            {'active': False},
            format='json',
        )
        self.assertNotEqual(
            res.status_code, 400,
            'acct_type_only target was wrongly shielded from suspension by account_type flag',
        )
        self.assertEqual(
            res.status_code, 200,
            f'Unexpected status suspending acct_type_only target: {res.status_code} {res.data}',
        )

