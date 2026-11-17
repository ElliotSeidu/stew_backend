import os
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from api.models import User, Vendor, Meal, Review, Compliance


class Command(BaseCommand):
    help = 'Creates the default STEW operations admin account (pass --demo to seed sample demo vendors/dishes for local testing)'

    def add_arguments(self, parser):
        parser.add_argument(
            '--demo',
            action='store_true',
            help='Also seed demo student users, sample vendors, and sample dishes',
        )
        parser.add_argument(
            '--reset-admin-password',
            action='store_true',
            help='Explicitly reset the default ops admin password if the account already exists',
        )

    def handle(self, *args, **options):
        is_debug = getattr(settings, 'DEBUG', False)
        if not is_debug:
            if options.get('demo'):
                raise CommandError('Refusing to seed --demo accounts when DEBUG=False.')
            seed_pw = os.getenv('SEED_ADMIN_PASSWORD', '')
            if len(seed_pw) < 12:
                raise CommandError('SEED_ADMIN_PASSWORD (at least 12 characters) is required when DEBUG=False.')
        else:
            seed_pw = os.getenv('SEED_ADMIN_PASSWORD', '') or 'admin1234'

        admin_user, created = User.objects.get_or_create(
            email='admin@st.knust.edu.gh',
            defaults={
                'full_name': 'STEW Operations Admin',
                'reference_id': '20819999',
                'phone': '0257059777',
                'hall': 'Commercial Area',
                'role': 'admin',
                'account_type': 'admin',
                'is_admin': True,
                'is_staff': True,
                'is_superuser': True,
                'verified': True,
            }
        )
        if created or options.get('reset_admin_password'):
            admin_user.set_password(seed_pw)
        admin_user.is_admin = True
        admin_user.is_staff = True
        admin_user.is_superuser = True
        admin_user.verified = True
        admin_user.save()

        if not options.get('demo'):
            self.stdout.write(self.style.SUCCESS("Verified STEW Operations Admin account (no dummy data seeded)."))
            return

        self.stdout.write("Seeding KNUST demo student users and vendors...")

        # 1. Accounts
        demo_user, _ = User.objects.get_or_create(
            email='demo@st.knust.edu.gh',
            defaults={
                'full_name': 'Kofi Asante',
                'reference_id': '20812345',
                'phone': '0240000001',
                'hall': 'Unity Hall (Conti)',
                'role': 'customer',
                'account_type': 'customer',
                'verified': True,
            }
        )
        demo_user.set_password('demo1234')
        demo_user.verified = True
        demo_user.save()

        vendor_user, _ = User.objects.get_or_create(
            email='vendor@st.knust.edu.gh',
            defaults={
                'full_name': 'Ama Serwaa',
                'reference_id': '20812346',
                'phone': '0240000002',
                'hall': 'Unity Hall (Conti)',
                'role': 'vendor',
                'account_type': 'vendor',
                'is_vendor': True,
                'kitchen_name': "Auntie Ama's Soup Pot",
                'sells': ['Palm nut soup (abenkwan)', 'Groundnut soup', 'Fufu (2 balls)', 'Egg stew'],
                'verified': True,
            }
        )
        vendor_user.set_password('vendor1234')
        vendor_user.is_vendor = True
        vendor_user.verified = True
        vendor_user.save()

        both_user, _ = User.objects.get_or_create(
            email='both@st.knust.edu.gh',
            defaults={
                'full_name': 'Kwame Mensah',
                'reference_id': '20812347',
                'phone': '0240000003',
                'hall': 'Queen Elizabeth II Hall (Queens)',
                'role': 'vendor',
                'account_type': 'both',
                'is_vendor': True,
                'kitchen_name': "Mama Efua's Kitchen",
                'sells': ['Light soup with goat', 'Kontomire with egg', 'Rice balls (2)'],
                'verified': True,
            }
        )
        both_user.set_password('both1234')
        both_user.is_vendor = True
        both_user.verified = True
        both_user.save()

        # 2. Vendors
        VENDORS_DATA = [
            {'id': 'v1', 'name': "Auntie Ama's Soup Pot", 'hall': 'Unity Hall (Conti)', 'rating': 4.8, 'reviews': 112, 'open': True, 'prep': 6, 'bio': 'One pot of soup a week. Palm nut, groundnut and light soup, cooked slow and portioned the same day.', 'user': vendor_user},
            {'id': 'v2', 'name': "Mama Efua's Kitchen", 'hall': 'Queen Elizabeth II Hall (Queens)', 'rating': 4.7, 'reviews': 86, 'open': True, 'prep': 7, 'bio': 'Fufu and light soup with goat, plus kontomire on weekends.', 'user': both_user},
            {'id': 'v3', 'name': "Chef Kojo's Stews", 'hall': 'Africa Hall', 'rating': 4.6, 'reviews': 64, 'open': True, 'prep': 5, 'bio': 'Chicken and beef stews, cooked down properly. Rice and yam on the side.', 'user': None},
            {'id': 'v4', 'name': "Nana's Groundnut Pot", 'hall': 'University Hall (Katanga)', 'rating': 4.5, 'reviews': 51, 'open': True, 'prep': 6, 'bio': 'Groundnut soup, nkatenkwan style, with or without goat.', 'user': None},
            {'id': 'v5', 'name': "Esi's Swallow Kitchen", 'hall': 'Independence Hall (Indece)', 'rating': 4.9, 'reviews': 143, 'open': True, 'prep': 8, 'bio': 'Fresh banku, fufu and kenkey made the morning of your pickup day.', 'user': None},
            {'id': 'v6', 'name': "Yaw's Palm Nut", 'hall': 'Ayeduase', 'rating': 4.4, 'reviews': 38, 'open': False, 'prep': 7, 'bio': 'Abenkwan with fish and wele. Orders close when the pot is full.', 'user': None},
            {'id': 'v7', 'name': 'Maame Fresh Drinks', 'hall': 'Republic Hall', 'rating': 4.7, 'reviews': 77, 'open': True, 'prep': 2, 'bio': 'Sobolo and ginger drinks to go with your soup.', 'user': None},
        ]

        vendor_instances = {}
        for v in VENDORS_DATA:
            vendor, _ = Vendor.objects.update_or_create(
                id=v['id'],
                defaults={
                    'name': v['name'],
                    'hall': v['hall'],
                    'rating': v['rating'],
                    'reviews': v['reviews'],
                    'open': v['open'],
                    'prep': v['prep'],
                    'bio': v['bio'],
                    'user': v['user']
                }
            )
            vendor_instances[v['id']] = vendor

        # 3. Meals
        MEALS_DATA = [
            ('m1', 'v1', 'Palm nut soup (abenkwan)', 'Palm nut soup with smoked fish and wele, cooked down for hours.', 45.0, 'Soups', 20, ['soup'], '/foods/palm-nut-soup.jpg', 'Two portions'),
            ('m2', 'v1', 'Groundnut soup', 'Nkatenkwan with chicken and a little ginger heat.', 42.0, 'Soups', 16, ['soup'], '/foods/groundnut-soup.jpg', 'Two portions'),
            ('m3', 'v2', 'Light soup with goat', 'Peppery light soup with tender goat, no thickener.', 48.0, 'Soups', 12, ['soup'], '/foods/light-soup.jpg', 'Two portions'),
            ('m4', 'v2', 'Kontomire with egg', 'Cocoyam leaf stew with egg and smoked fish.', 35.0, 'Stews', 14, ['stew'], '/foods/kontomire-stew.jpg', 'Single portion'),
            ('m5', 'v4', 'Groundnut soup with goat', 'Rich groundnut base, goat on the bone.', 52.0, 'Soups', 10, ['soup'], '/foods/groundnut-soup.jpg', 'Two portions'),
            ('m6', 'v6', 'Palm nut soup with tilapia', 'Abenkwan with whole tilapia. Pot is limited.', 55.0, 'Soups', 8, ['soup'], '/foods/palm-nut-soup.jpg', 'Two portions'),
            ('m7', 'v3', 'Chicken stew', 'Slow-cooked chicken stew in tomato and pepper, plenty of gravy.', 40.0, 'Stews', 18, ['stew'], '/foods/chicken-stew.jpg', 'Two portions'),
            ('m8', 'v3', 'Beef stew', 'Beef simmered until soft, with a thick pepper base.', 45.0, 'Stews', 15, ['stew'], '/foods/beef-stew.jpg', 'Two portions'),
            ('m9', 'v3', 'Fish stew', 'Fried fish simmered in pepper and tomato.', 42.0, 'Stews', 12, ['stew'], '/foods/fish-stew.jpg', 'Single portion'),
            ('m10', 'v1', 'Egg stew', 'Boiled eggs in a light tomato stew, good with rice or yam.', 25.0, 'Stews', 22, ['stew'], '/foods/egg-stew.jpg', 'Single portion'),
            ('m11', 'v5', 'Fufu (2 balls)', 'Fresh pounded fufu, made the morning of your pickup day.', 12.0, 'Swallows', 30, ['swallow'], '/foods/fufu.jpg', 'Single portion'),
            ('m12', 'v5', 'Banku (2 balls)', 'Soft banku, fermented properly.', 10.0, 'Swallows', 28, ['swallow'], '/foods/banku.jpg', 'Single portion'),
            ('m13', 'v5', 'Kenkey (2 balls)', 'Ga kenkey with a little shito on the side.', 10.0, 'Swallows', 26, ['swallow'], '/foods/kenkey.jpg', 'Single portion'),
            ('m14', 'v2', 'Rice balls (2)', 'Moulded rice to go with your soup.', 10.0, 'Rice & sides', 20, ['side'], '/foods/rice-balls.jpg', 'Single portion'),
            ('m15', 'v7', 'Sobolo (500 ml)', 'Chilled hibiscus drink with ginger and cloves.', 8.0, 'Drinks', 40, ['drink'], '/foods/sobolo.jpg', 'Single portion'),
            ('m16', 'v7', 'Pineapple-ginger juice', 'Fresh-pressed, no added sugar.', 12.0, 'Drinks', 24, ['drink'], '/foods/pineapple-juice.jpg', 'Single portion'),
        ]

        for m_id, v_id, name, desc, price, cat, left, kinds, image, portion in MEALS_DATA:
            Meal.objects.update_or_create(
                id=m_id,
                defaults={
                    'vendor': vendor_instances[v_id],
                    'name': name,
                    'desc': desc,
                    'price': price,
                    'cat': cat,
                    'left': left,
                    'kinds': kinds,
                    'image': image,
                    'portion': portion,
                    'on': True,
                    'batch': True
                }
            )

        # 4. Sample Compliance Records
        Compliance.objects.update_or_create(
            vendor_id='esi@st.knust.edu.gh',
            defaults={
                'vendor_name': "Esi's Swallow Kitchen",
                'type': 'FDA food hygiene permit',
                'number': 'FDA/KN/2026/8841',
                'issued_at': '2026-02-01',
                'expires_at': '2027-02-01',
                'reviewed_by': 'admin@st.knust.edu.gh',
            }
        )
        Compliance.objects.update_or_create(
            vendor_id='yaw@st.knust.edu.gh',
            defaults={
                'vendor_name': "Yaw's Palm Nut",
                'type': 'FDA food hygiene permit',
                'number': 'FDA/KN/2025/1190',
                'issued_at': '2025-01-15',
                'expires_at': '2026-01-15',
                'reviewed_by': '',
            }
        )

        # 5. Sample Reviews
        SAMPLE_REVIEWS = [
            ('STW-1001', 'v1', "Auntie Ama's Soup Pot", 5, ['Tasty', 'Good portion', 'Fresh'], 'The abenkwan was incredible. Smoked fish and wele were fresh and tender.', 'visible'),
            ('STW-1002', 'v1', "Auntie Ama's Soup Pot", 5, ['Hot', 'Tasty'], 'Groundnut soup was well spiced and delivered hot at Unity hall.', 'visible'),
            ('STW-1003', 'v2', "Mama Efua's Kitchen", 5, ['Tasty', 'Fast'], 'Light soup goat meat is very soft and spicy!', 'visible'),
            ('STW-1004', 'v3', "Chef Kojo's Stews", 4, ['Good value'], 'Very generous chicken portion. Highly recommended for students.', 'pending'),
        ]
        for ord_id, v_id, v_name, rating, tags, text, mod_status in SAMPLE_REVIEWS:
            Review.objects.update_or_create(
                order_id=ord_id,
                defaults={
                    'vendor': vendor_instances[v_id],
                    'vendor_name': v_name,
                    'customer': demo_user,
                    'rating': rating,
                    'tags': tags,
                    'text': text,
                    'moderation_status': mod_status,
                }
            )

        self.stdout.write(self.style.SUCCESS('Successfully seeded database with KNUST student data!'))
