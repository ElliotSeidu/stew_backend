import time
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient
from api.models import User, Vendor, Meal, Order, Review
from api.security import generate_jwt_token, hash_token, _RATE_LIMIT_CACHE


class SecurityAnalystAndKNUSTPolicyTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Legitimate student user
        cls.student = User.objects.create_user(
            email='kofi.boateng@st.knust.edu.gh',
            password='Password123',
            full_name='Kofi Boateng',
            reference_id='20811111',
            phone='0241111111',
            hall='Unity Hall (Conti)',
            verified=True,
            role='customer',
            account_type='customer'
        )
        cls.student_token = generate_jwt_token(cls.student)

        # Another student (victim)
        cls.victim_student = User.objects.create_user(
            email='abena.yaa@st.knust.edu.gh',
            password='Password123',
            full_name='Abena Yaa',
            reference_id='20822222',
            phone='0242222222',
            hall='Africa Hall',
            verified=True,
            role='customer',
            account_type='customer'
        )
        cls.victim_token = generate_jwt_token(cls.victim_student)

        # Vendor user
        cls.vendor_user = User.objects.create_user(
            email='auntie.ama@st.knust.edu.gh',
            password='Password123',
            full_name='Ama Serwaa',
            reference_id='20833333',
            phone='0243333333',
            hall='Unity Hall (Conti)',
            verified=True,
            role='vendor',
            account_type='vendor',
            is_vendor=True,
            kitchen_name="Auntie Ama's Soup Pot"
        )
        cls.vendor_token = generate_jwt_token(cls.vendor_user)

        cls.vendor = Vendor.objects.create(
            id='v1',
            user=cls.vendor_user,
            name="Auntie Ama's Soup Pot",
            hall='Unity Hall (Conti)',
            rating=4.8,
            reviews=10,
            open=True
        )

        cls.meal = Meal.objects.create(
            id='m1',
            vendor=cls.vendor,
            name='Palm nut soup (abenkwan)',
            price=45.0,
            cat='Soups',
            left=10,
            on=True
        )

        # Admin user
        cls.admin_user = User.objects.create_superuser(
            email='admin.officer@st.knust.edu.gh',
            password='AdminPassword123',
            full_name='Admin Officer'
        )
        cls.admin_token = generate_jwt_token(cls.admin_user)

    def setUp(self):
        _RATE_LIMIT_CACHE.clear()
        self.client = APIClient()

    # ------------------------------------------------------------------------
    # 1. KNUST Student Email Enforcement Security Audit
    # ------------------------------------------------------------------------

    def test_registration_strictly_rejects_non_knust_emails(self):
        """Security check: Gmail, Yahoo, Hotmail, Outlook or non-student domains MUST be rejected."""
        forbidden_emails = [
            'hacker@gmail.com',
            'intruder@yahoo.com',
            'attacker@outlook.com',
            'student@hotmail.com',
            'lecturer@knust.edu.gh',  # Staff/non-student email
            'fake@st.knust.edu.gh.attacker.com',  # Subdomain trick
            'fake@attacker.st.knust.edu.gh',
        ]

        for bad_email in forbidden_emails:
            res = self.client.post('/api/auth/register/', {
                'fullName': 'Attacker Test',
                'email': bad_email,
                'referenceId': '20855555',
                'phone': '0245555555',
                'password': 'Password123',
                'accountType': 'customer'
            }, format='json')
            self.assertEqual(res.status_code, 400, f"Registration failed to reject illegal email: {bad_email}")

    def test_registration_accepts_valid_knust_student_email(self):
        """Legitimate student with @st.knust.edu.gh is accepted."""
        res = self.client.post('/api/auth/register/', {
            'fullName': 'Yaw Frimpong',
            'email': 'y.frimpong@st.knust.edu.gh',
            'referenceId': '20866666',
            'phone': '0246666666',
            'password': 'Password123',
            'accountType': 'customer'
        }, format='json')
        self.assertEqual(res.status_code, 201)
        self.assertTrue(User.objects.filter(email='y.frimpong@st.knust.edu.gh').exists())

    def test_login_rejects_non_knust_emails(self):
        """Non-KNUST email attempt on login endpoint is rejected."""
        res = self.client.post('/api/auth/login/', {
            'email': 'hacker@gmail.com',
            'password': 'Password123'
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('KNUST student', res.data.get('message', ''))

    def test_forgot_password_rejects_non_knust_emails(self):
        """Non-KNUST email on forgot-password is rejected."""
        res = self.client.post('/api/auth/forgot-password/', {'email': 'test@gmail.com'}, format='json')
        self.assertEqual(res.status_code, 400)

    def test_profile_update_rejects_non_knust_email(self):
        """Student cannot change profile email to a non-KNUST email."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.patch('/api/auth/me/', {'email': 'switch_to_gmail@gmail.com'}, format='json')
        self.assertEqual(res.status_code, 400)

    # ------------------------------------------------------------------------
    # 2. Authentication & Verification Enforcement
    # ------------------------------------------------------------------------

    def test_unverified_student_cannot_log_in(self):
        """Unverified accounts receive code 'unverified' and cannot obtain session tokens."""
        unverified_student = User.objects.create_user(
            email='unverified.user@st.knust.edu.gh',
            password='Password123',
            full_name='Unverified User',
            verified=False
        )
        res = self.client.post('/api/auth/login/', {
            'email': 'unverified.user@st.knust.edu.gh',
            'password': 'Password123'
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertEqual(res.data.get('code'), 'unverified')

    def test_forged_jwt_token_is_rejected(self):
        """Forged or tampered JWT tokens return 401 Unauthorized."""
        tampered_token = self.student_token[:-5] + 'ABCDE'
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tampered_token}')
        res = self.client.get('/api/auth/me/')
        self.assertEqual(res.status_code, 401)

    # ------------------------------------------------------------------------
    # 3. IDOR (Insecure Direct Object Reference) Protection
    # ------------------------------------------------------------------------

    def test_student_cannot_access_or_cancel_another_students_order(self):
        """IDOR defense: Student A cannot inspect or manipulate Student B's order."""
        # Create order for Victim Student
        order = Order.objects.create(
            id='STW-9999',
            customer=self.victim_student,
            customer_name='Abena Yaa',
            email=self.victim_student.email,
            phone=self.victim_student.phone,
            area='Africa Hall',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='654321',
            pickup_day='2026-10-20',
            prep_stage='accepted',
            payment_status='pending'
        )

        # Attacker tries to read Victim's order
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.get(f'/api/orders/{order.id}/')
        self.assertEqual(res.status_code, 403, "IDOR detected: Attacker could view victim order!")

        # Attacker tries to cancel Victim's order
        res_cancel = self.client.post(f'/api/orders/{order.id}/cancel/')
        self.assertEqual(res_cancel.status_code, 403, "IDOR detected: Attacker could cancel victim order!")

    # ------------------------------------------------------------------------
    # 4. Escrow & Handover Invariant Enforcement
    # ------------------------------------------------------------------------

    def test_handoff_code_constant_time_verification_and_escrow_release(self):
        """Chef verifying handover code successfully releases escrow funds to chef."""
        order = Order.objects.create(
            id='STW-7777',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='123456',
            pickup_day='2026-10-20',
            prep_stage='ready',
            payment_status='paid',
            settlement_status='pending'
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')

        # Try incorrect code
        res_wrong = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '999999'}, format='json')
        self.assertEqual(res_wrong.status_code, 400)
        order.refresh_from_db()
        self.assertEqual(order.settlement_status, 'pending')

        # Enter correct code
        res_correct = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '123456'}, format='json')
        self.assertEqual(res_correct.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.prep_stage, 'collected')
        self.assertEqual(order.settlement_status, 'released')
        self.assertEqual(order.payment_status, 'released')
        self.assertEqual(order.settlement_net, 45.0)

    def test_student_confirm_collection_releases_escrow(self):
        """Student confirming collection marks order collected and releases escrow funds."""
        order = Order.objects.create(
            id='STW-8888',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='654321',
            pickup_day='2026-10-20',
            prep_stage='ready',
            payment_status='paid',
            settlement_status='pending'
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.post(f'/api/orders/{order.id}/collected/')
        self.assertEqual(res.status_code, 200)
        order.refresh_from_db()
        self.assertEqual(order.prep_stage, 'collected')
        self.assertEqual(order.settlement_status, 'released')
        self.assertEqual(order.payment_status, 'released')

    def test_cannot_review_uncollected_order(self):
        """A review can only be submitted AFTER the order is collected."""
        order = Order.objects.create(
            id='STW-5555',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='654321',
            pickup_day='2026-10-20',
            prep_stage='cooking',
            payment_status='paid'
        )

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.post('/api/reviews/', {
            'orderId': order.id,
            'rating': 5,
            'text': 'Tasted amazing!'
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertIn('only review an order you have collected', res.data.get('message', ''))

    # ------------------------------------------------------------------------
    # 5. Privileged Account Protection
    # ------------------------------------------------------------------------

    def test_admin_account_cannot_be_deleted(self):
        """Administrative accounts are protected against accidental or malicious deletion."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res = self.client.delete('/api/auth/delete-account/')
        self.assertEqual(res.status_code, 400)
        self.assertTrue(User.objects.filter(id=self.admin_user.id).exists())

    # ------------------------------------------------------------------------
    # 6. Full Marketplace Lifecycle & Escrow Flow
    # ------------------------------------------------------------------------

    @override_settings(DEBUG=True, PAYSTACK_ALLOW_MOCK=True)
    def test_complete_order_placement_payment_and_meetup_flow(self):
        """Tests complete order creation, 5% fee calculation, Paystack init/verify, and meetup."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')

        # Step 1: Place Order
        order_res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'vendorName': self.vendor.name,
            'lines': [{'mealId': self.meal.id, 'name': self.meal.name, 'price': self.meal.price, 'qty': 2, 'note': 'Small pepper'}],
            'subtotal': 90.0,
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22',
            'pickupSlot': 'evening',
            'phone': '0241111111'
        }, format='json')
        self.assertEqual(order_res.status_code, 201)
        order_data = order_res.data
        order_id = order_data['id']
        self.assertEqual(order_data['subtotal'], 90.0)
        self.assertEqual(order_data['fee'], 4.50)  # 5% of 90
        self.assertEqual(order_data['total'], 94.50)
        self.assertIsNotNone(order_data['handoffCode'])

        # Step 2: Initialize Payment
        init_res = self.client.post('/api/payments/initialize/', {'orderId': order_id}, format='json')
        self.assertEqual(init_res.status_code, 200)
        ref = init_res.data['reference']
        self.assertTrue(ref.startswith('PSK-'))

        # Step 3: Verify Payment (funds held in escrow)
        ver_res = self.client.post('/api/payments/verify/', {'orderId': order_id, 'reference': ref}, format='json')
        self.assertEqual(ver_res.status_code, 200)
        self.assertEqual(ver_res.data['payment']['status'], 'paid')
        self.assertEqual(ver_res.data['settlement']['status'], 'pending')

        # Step 4: Propose Meetup
        meetup_res = self.client.post(f'/api/orders/{order_id}/meetup/propose/', {
            'place': 'Commercial Area pharmacy row',
            'note': 'Beside the blue kiosk',
            'proposedBy': 'student'
        }, format='json')
        self.assertEqual(meetup_res.status_code, 200)
        self.assertFalse(meetup_res.data['meetup']['agreed'])

        # Step 5: Vendor confirms Meetup -> agreed becomes True
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        confirm_res = self.client.post(f'/api/orders/{order_id}/meetup/confirm/')
        self.assertEqual(confirm_res.status_code, 200)
        self.assertTrue(confirm_res.data['meetup']['agreed'])

    def test_vendor_can_manage_dishes(self):
        """Chef can create, edit and delete dishes on their menu."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')

        # Create dish
        res = self.client.post('/api/meals/', {
            'name': 'Light soup with goat',
            'price': 48.0,
            'desc': 'Authentic peppery light soup',
            'cat': 'Soups',
            'stock': 15
        }, format='json')
        self.assertEqual(res.status_code, 201)
        meal_id = res.data['id']

        # Edit dish
        edit_res = self.client.patch(f'/api/meals/{meal_id}/', {
            'price': 50.0,
            'on': False
        }, format='json')
        self.assertEqual(edit_res.status_code, 200)
        self.assertEqual(edit_res.data['price'], 50.0)
        self.assertFalse(edit_res.data['on'])

        # Delete dish
        del_res = self.client.delete(f'/api/meals/{meal_id}/')
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(Meal.objects.filter(id=meal_id).exists())

    # ------------------------------------------------------------------------
    # 7. Round 2 Deep Security Audit Regressions
    # ------------------------------------------------------------------------

    def test_self_registration_as_admin_is_blocked(self):
        """Privilege escalation check: Attacker cannot register with accountType='admin'."""
        res = self.client.post('/api/auth/register/', {
            'fullName': 'Escalation Attacker',
            'email': 'escalate@st.knust.edu.gh',
            'referenceId': '20899999',
            'phone': '0249999999',
            'password': 'Password123',
            'accountType': 'admin'
        }, format='json')
        self.assertEqual(res.status_code, 400)
        self.assertFalse(User.objects.filter(email='escalate@st.knust.edu.gh').exists())

    def test_unpaid_order_cannot_be_completed_by_handoff_code(self):
        """Escrow fraud check: Vendor cannot complete an unpaid order and fabricate released payout."""
        order = Order.objects.create(
            id='STW-UNPAID',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='112233',
            pickup_day='2026-10-20',
            prep_stage='ready',
            payment_status='pending',
            settlement_status='pending'
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        res = self.client.post(f'/api/orders/{order.id}/complete/', {'code': '112233'}, format='json')
        self.assertEqual(res.status_code, 400)
        order.refresh_from_db()
        self.assertEqual(order.settlement_status, 'pending')
        self.assertNotEqual(order.prep_stage, 'collected')

    def test_cross_vendor_and_third_party_idor_on_order_endpoints(self):
        """IDOR check: Rival vendor or unrelated student cannot mutate order state, payment, meetup, or chat."""
        rival_user = User.objects.create_user(
            email='rival.chef@st.knust.edu.gh',
            password='Password123',
            full_name='Rival Chef',
            reference_id='20844444',
            phone='0244444444',
            verified=True,
            role='vendor',
            account_type='vendor',
            is_vendor=True
        )
        Vendor.objects.create(id='v2', user=rival_user, name='Rival Pot', hall='Queens Hall', open=True)
        rival_token = generate_jwt_token(rival_user)

        order = Order.objects.create(
            id='STW-IDOR1',
            customer=self.victim_student,
            customer_name='Abena Yaa',
            email=self.victim_student.email,
            phone=self.victim_student.phone,
            area='Africa Hall',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='445566',
            pickup_day='2026-10-20',
            prep_stage='accepted',
            payment_status='paid'
        )

        # Rival vendor attempts to change prep stage, complete, or nudge
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {rival_token}')
        self.assertEqual(self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'cooking'}, format='json').status_code, 403)
        self.assertEqual(self.client.post(f'/api/orders/{order.id}/complete/', {'code': '445566'}, format='json').status_code, 403)
        self.assertEqual(self.client.post(f'/api/orders/{order.id}/collection-nudge/').status_code, 403)

        # Unrelated student attempts to init payment, propose meetup, or send chat message
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        self.assertEqual(self.client.post('/api/payments/initialize/', {'orderId': order.id}, format='json').status_code, 403)
        self.assertEqual(self.client.post(f'/api/orders/{order.id}/meetup/propose/', {'place': 'Library'}, format='json').status_code, 403)
        self.assertEqual(self.client.post(f'/api/orders/{order.id}/messages/', {'text': 'Spying'}, format='json').status_code, 403)

    def test_set_prep_stage_cannot_mark_collected_without_handoff(self):
        """Vendor cannot bypass handoff code by setting prep_stage='collected' directly."""
        order = Order.objects.create(
            id='STW-STAGE1',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='778899',
            pickup_day='2026-10-20',
            prep_stage='ready',
            payment_status='paid'
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        res = self.client.post(f'/api/orders/{order.id}/prep/', {'stage': 'collected'}, format='json')
        self.assertEqual(res.status_code, 400)

    def test_authoritative_db_meal_price_enforced_against_client_tampering(self):
        """Client sending tampered price=1.0 for a 45.0 GHS DB meal is overridden with 45.0 GHS."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'vendorName': self.vendor.name,
            'lines': [{'mealId': self.meal.id, 'name': self.meal.name, 'price': 1.0, 'qty': 2}],
            'subtotal': 2.0,
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22'
        }, format='json')
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.data['subtotal'], 90.0)
        self.assertEqual(res.data['total'], 94.5)

    def test_hidden_reviews_not_leaked_to_unauthenticated_or_non_admin(self):
        """?includeHidden=true only returns hidden reviews when called by an authenticated admin."""
        Review.objects.create(
            order_id='STW-REV1',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            customer=self.student,
            rating=5,
            text='Visible review',
            moderation_status='visible'
        )
        Review.objects.create(
            order_id='STW-REV2',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            customer=self.victim_student,
            rating=1,
            text='Moderated hidden review',
            moderation_status='hidden'
        )

        # Unauthenticated caller with ?includeHidden=true
        self.client.credentials()
        res_anon = self.client.get(f'/api/vendors/{self.vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(res_anon.status_code, 200)
        self.assertEqual(len(res_anon.data), 1)
        self.assertEqual(res_anon.data[0]['orderId'], 'STW-REV1')

        # Non-admin student caller with ?includeHidden=true
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        res_student = self.client.get(f'/api/vendors/{self.vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(res_student.status_code, 200)
        self.assertEqual(len(res_student.data), 1)

        # Admin caller with ?includeHidden=true
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        res_admin = self.client.get(f'/api/vendors/{self.vendor.id}/reviews/?includeHidden=true')
        self.assertEqual(res_admin.status_code, 200)
        self.assertEqual(len(res_admin.data), 2)

    def test_support_case_frontend_payload_compatibility(self):
        """Support.jsx sends { type, orderId, description }; backend stores and returns both conventions."""
        order = Order.objects.create(
            id='STW-SUP1',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='121212',
            pickup_day='2026-10-20',
            prep_stage='ready',
            payment_status='paid'
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        create_res = self.client.post('/api/support/cases/', {
            'type': 'handoff',
            'orderId': order.id,
            'description': 'Chef has not arrived at pickup point yet.'
        }, format='json')
        self.assertEqual(create_res.status_code, 201)
        self.assertEqual(create_res.data['orderId'], order.id)
        self.assertEqual(create_res.data['order'], order.id)
        self.assertEqual(create_res.data['description'], 'Chef has not arrived at pickup point yet.')
        self.assertEqual(create_res.data['vendor'], self.vendor.name)

        list_res = self.client.get('/api/support/cases/')
        self.assertEqual(list_res.status_code, 200)
        self.assertEqual(len(list_res.data), 1)
        self.assertEqual(list_res.data[0]['orderId'], order.id)

    def test_review_creation_and_admin_moderation_lifecycle(self):
        """Student submits review on collected order -> pending -> Admin moderates to visible -> vendor rating updates."""
        order = Order.objects.create(
            id='STW-MOD1',
            customer=self.student,
            customer_name='Kofi Boateng',
            email=self.student.email,
            phone=self.student.phone,
            area='Unity Hall (Conti)',
            vendor=self.vendor,
            vendor_name=self.vendor.name,
            lines=[{'mealId': 'm1', 'name': 'Palm nut soup', 'price': 45, 'qty': 1}],
            subtotal=45.0,
            fee=2.25,
            total=47.25,
            handoff_code='343434',
            pickup_day='2026-10-20',
            prep_stage='collected',
            payment_status='released',
            settlement_status='released'
        )
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        rev_res = self.client.post('/api/reviews/', {
            'orderId': order.id,
            'rating': 5,
            'tags': ['Hot & fresh', 'Generous portion'],
            'text': 'Best abenkwan on campus!'
        }, format='json')
        self.assertEqual(rev_res.status_code, 201)
        self.assertEqual(rev_res.data['moderationStatus'], 'pending')

        # Admin views moderation queue and approves review
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        q_res = self.client.get('/api/admin/reviews/queue/')
        self.assertEqual(q_res.status_code, 200)
        self.assertTrue(any(r['orderId'] == order.id for r in q_res.data))

        # Invalid decision rejected
        bad_mod = self.client.post(f'/api/admin/reviews/{order.id}/moderate/', {'decision': 'hacked'}, format='json')
        self.assertEqual(bad_mod.status_code, 400)

        # Valid decision accepted
        ok_mod = self.client.post(f'/api/admin/reviews/{order.id}/moderate/', {'decision': 'visible'}, format='json')
        self.assertEqual(ok_mod.status_code, 200)
        self.assertEqual(ok_mod.data['moderationStatus'], 'visible')

    def test_push_notification_https_enforcement_and_owner_scoping(self):
        """Push subscription requires https:// endpoint and cannot be unsubscribed by another user."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        bad_sub = self.client.post('/api/notifications/subscribe/', {
            'endpoint': 'http://insecure.example.com/push/123',
            'keys': {'p256dh': 'abc', 'auth': 'def'}
        }, format='json')
        self.assertEqual(bad_sub.status_code, 400)

        good_sub = self.client.post('/api/notifications/subscribe/', {
            'endpoint': 'https://fcm.googleapis.com/fcm/send/student123',
            'keys': {'p256dh': 'abc', 'auth': 'def'}
        }, format='json')
        self.assertEqual(good_sub.status_code, 201)

        # Another user tries to unsubscribe student's endpoint
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.victim_token}')
        unsub_other = self.client.post('/api/notifications/unsubscribe/', {
            'endpoint': 'https://fcm.googleapis.com/fcm/send/student123'
        }, format='json')
        self.assertEqual(unsub_other.status_code, 200)

        # Verify subscription still exists for original student
        from api.models import PushSubscription
        self.assertTrue(PushSubscription.objects.filter(endpoint='https://fcm.googleapis.com/fcm/send/student123', user=self.student).exists())

    # ------------------------------------------------------------------------
    # 8. Round 3 Hardening: Session Revocation, Stock Locks, & Webhook HMAC
    # ------------------------------------------------------------------------

    def test_password_reset_revokes_previous_jwt_tokens(self):
        """Changing or resetting password changes the password fingerprint (pv) and invalidates old JWTs."""
        temp_user = User.objects.create_user(
            email='temp.student@st.knust.edu.gh',
            password='OldPassword123',
            full_name='Temp Student',
            reference_id='20877777',
            phone='0247777777',
            verified=True
        )
        old_token = generate_jwt_token(temp_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {old_token}')
        self.assertEqual(self.client.get('/api/auth/me/').status_code, 200)

        # Simulate password change/reset
        temp_user.set_password('NewPassword456')
        temp_user.save(update_fields=['password'])

        # Old token must now be rejected with 401
        self.assertEqual(self.client.get('/api/auth/me/').status_code, 401)

    def test_order_stock_decrement_and_restoration_on_cancel(self):
        """Placing an order decrements Meal.left, blocks over-ordering, and restores stock on cancel."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        initial_left = Meal.objects.get(id=self.meal.id).left

        # Over-ordering beyond available stock is rejected
        over_res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'lines': [{'mealId': self.meal.id, 'name': self.meal.name, 'price': self.meal.price, 'qty': initial_left + 5}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22'
        }, format='json')
        self.assertEqual(over_res.status_code, 400)

        # Valid order decrements stock
        ok_res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'lines': [{'mealId': self.meal.id, 'name': self.meal.name, 'price': self.meal.price, 'qty': 3}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22'
        }, format='json')
        self.assertEqual(ok_res.status_code, 201)
        self.assertEqual(Meal.objects.get(id=self.meal.id).left, initial_left - 3)

        # Cancelling within window restores stock
        order_id = ok_res.data['id']
        cancel_res = self.client.post(f'/api/orders/{order_id}/cancel/')
        self.assertEqual(cancel_res.status_code, 200)
        self.assertEqual(Meal.objects.get(id=self.meal.id).left, initial_left)

    def test_self_dealing_and_unknown_meal_rejected(self):
        """A vendor cannot place an order at their own kitchen, and fabricated mealIds are rejected."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        self_res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'lines': [{'mealId': self.meal.id, 'name': self.meal.name, 'price': self.meal.price, 'qty': 1}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22'
        }, format='json')
        self.assertEqual(self_res.status_code, 400)

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        fake_res = self.client.post('/api/orders/', {
            'vendorId': self.vendor.id,
            'lines': [{'mealId': 'm_nonexistent', 'name': 'Fake Dish', 'price': 1.0, 'qty': 1}],
            'area': 'Unity Hall (Conti)',
            'pickupDay': '2026-10-22'
        }, format='json')
        self.assertEqual(fake_res.status_code, 400)

    def test_paystack_webhook_rejects_invalid_signature(self):
        """Paystack webhook requires a valid HMAC-SHA512 X-Paystack-Signature."""
        from django.test import override_settings
        with override_settings(PAYSTACK_SECRET_KEY='sk_test_webhook_secret'):
            self.client.credentials()
            res = self.client.post(
                '/api/payments/webhook/',
                data='{"event":"charge.success","data":{"reference":"PSK-123"}}',
                content_type='application/json',
                HTTP_X_PAYSTACK_SIGNATURE='invalid_signature_hex'
            )
            self.assertEqual(res.status_code, 401)

    def test_vendor_onboarding_and_menu_crud(self):
        """Vendor setup saves kitchen + logo, returns updated user with vendorId, and supports ?mine=true menu CRUD."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')
        apply_res = self.client.post('/api/vendor/apply/', {
            'kitchen': "Ama's Gold Pot",
            'hall': 'Unity Hall (Conti)',
            'sells': ['Palm nut soup', 'Fufu'],
            'about': 'Slow cooked palm nut soup every weekend for Unity Hall.',
            'payout': '0242222222',
            'logo': 'data:image/jpeg;base64,/9j/4AAQSkZJRg=='
        }, format='json')
        self.assertEqual(apply_res.status_code, 200)
        self.assertTrue(apply_res.data['user']['vendorId'])
        self.assertEqual(apply_res.data['user']['kitchenName'], "Ama's Gold Pot")

        # Create dish
        meal_res = self.client.post('/api/meals/', {
            'name': 'Special Abenkwan',
            'price': 50,
            'stock': 12,
            'cat': 'Soups',
            'desc': 'Rich palm nut soup with smoked fish.'
        }, format='json')
        self.assertEqual(meal_res.status_code, 201)
        meal_id = meal_res.data['id']

        # Toggle off menu
        patch_res = self.client.patch(f'/api/meals/{meal_id}/', {'on': False}, format='json')
        self.assertEqual(patch_res.status_code, 200)
        self.assertFalse(patch_res.data['on'])

        # Vendor still sees off-menu dish via ?mine=true
        mine_res = self.client.get('/api/meals/?mine=true')
        self.assertEqual(mine_res.status_code, 200)
        self.assertTrue(any(m['id'] == meal_id for m in mine_res.data))

        # Public catalogue hides off-menu dish
        pub_res = self.client.get('/api/meals/')
        self.assertEqual(pub_res.status_code, 200)
        self.assertFalse(any(m['id'] == meal_id for m in pub_res.data))

    def test_admin_management_and_case_resolution(self):
        """Admin can list/manage vendors, users, audit logs, and resolve support cases; students get 403."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.student_token}')
        self.assertEqual(self.client.get('/api/admin/vendors/').status_code, 403)
        self.assertEqual(self.client.get('/api/admin/users/').status_code, 403)
        self.assertEqual(self.client.get('/api/admin/audit/').status_code, 403)

        case_res = self.client.post('/api/support/cases/', {
            'type': 'missing',
            'note': 'Missing fufu ball'
        }, format='json')
        self.assertEqual(case_res.status_code, 201)
        code = case_res.data['code']

        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.admin_token}')
        self.assertEqual(self.client.get('/api/admin/vendors/').status_code, 200)
        self.assertEqual(self.client.get('/api/admin/users/').status_code, 200)
        self.assertEqual(self.client.get('/api/admin/audit/').status_code, 200)

        resolve_res = self.client.post(f'/api/support/cases/{code}/resolve/', {'action': 'dismiss'}, format='json')
        self.assertEqual(resolve_res.status_code, 200)

    def test_otp_never_printed_when_debug_is_false(self):
        """Ensure _dispatch_otp_email never prints OTP codes to stdout when DEBUG=False."""
        import io
        from contextlib import redirect_stdout
        from django.test import override_settings
        from api.views import _dispatch_otp_email

        buf = io.StringIO()
        with override_settings(DEBUG=False, EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend'):
            with redirect_stdout(buf):
                _dispatch_otp_email('student@st.knust.edu.gh', '987654', 'Email Verification')
        self.assertNotIn('987654', buf.getvalue())

    def test_negative_price_or_stock_rejected_and_no_default_ratings_until_reviewed(self):
        """Negative price or stock is rejected with 400; new kitchens/meals start with rating=0 until reviewed."""
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {self.vendor_token}')

        # Negative stock rejected
        neg_stock = self.client.post('/api/meals/', {
            'name': 'Negative Stock Dish',
            'price': 30,
            'stock': -5,
            'cat': 'Soups',
            'desc': 'Should fail validation'
        }, format='json')
        self.assertEqual(neg_stock.status_code, 400)

        # Negative price rejected
        neg_price = self.client.post('/api/meals/', {
            'name': 'Negative Price Dish',
            'price': -10,
            'stock': 5,
            'cat': 'Soups',
            'desc': 'Should fail validation'
        }, format='json')
        self.assertEqual(neg_price.status_code, 400)

        # New vendor starts with rating=0 and reviews=0
        new_vendor_user = User.objects.create_user(
            email='new.chef@st.knust.edu.gh',
            password='Password123',
            full_name='New Chef',
            reference_id='20812345',
            phone='0241234567',
            verified=True,
            role='vendor',
            account_type='vendor',
            is_vendor=True
        )
        new_token = generate_jwt_token(new_vendor_user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {new_token}')
        self.client.post('/api/vendor/apply/', {
            'kitchen': 'Fresh Pot Kitchen',
            'hall': 'Queens Hall',
            'sells': ['Jollof'],
            'about': 'Freshly cooked smoky jollof every weekend.',
            'payout': '0241234567'
        }, format='json')
        fresh_vendor = Vendor.objects.get(user=new_vendor_user)
        self.assertEqual(fresh_vendor.rating, 0.0)
        self.assertEqual(fresh_vendor.reviews, 0)

        meal_res = self.client.post('/api/meals/', {
            'name': 'Smoky Jollof',
            'price': 35,
            'stock': 8,
            'cat': 'Rice & stews',
            'desc': 'Firewood style jollof with chicken.'
        }, format='json')
        self.assertEqual(meal_res.status_code, 201)
        self.assertEqual(meal_res.data['rating'], 0)
        self.assertEqual(meal_res.data['reviews'], 0)





