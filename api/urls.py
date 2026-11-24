from django.urls import path
from api import views

urlpatterns = [
    # Auth
    path('auth/register/', views.register_view, name='register'),
    path('auth/verify-email/', views.verify_email_view, name='verify_email'),
    path('auth/resend-code/', views.resend_code_view, name='resend_code'),
    path('auth/login/', views.login_view, name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/forgot-password/', views.forgot_password_view, name='forgot_password'),
    path('auth/reset-password/', views.reset_password_view, name='reset_password'),
    path('auth/login-code/request/', views.request_login_code_view, name='request_login_code'),
    path('auth/login-code/verify/', views.login_with_code_view, name='login_with_code'),
    path('auth/check-reference/', views.check_reference_view, name='check_reference'),
    path('auth/me/', views.me_view, name='me'),
    path('auth/delete-account/', views.delete_account_view, name='delete_account'),

    # Vendors & Meals
    path('vendors/', views.vendors_list_view, name='vendors_list'),
    path('vendors/<str:pk>/', views.vendor_detail_view, name='vendor_detail'),
    path('vendors/<str:vendorId>/reviews/', views.vendor_reviews_view, name='vendor_reviews'),
    path('meals/', views.meals_list_view, name='meals_list'),
    path('meals/<str:pk>/', views.meal_detail_view, name='meal_detail'),

    # Orders & Escrow
    path('orders/', views.orders_view, name='orders'),
    path('orders/<str:pk>/', views.order_detail_view, name='order_detail'),
    path('orders/<str:pk>/cancel/', views.cancel_order_view, name='cancel_order'),
    path('orders/<str:pk>/meetup/propose/', views.propose_meetup_view, name='propose_meetup'),
    path('orders/<str:pk>/meetup/confirm/', views.confirm_meetup_view, name='confirm_meetup'),
    path('orders/<str:pk>/meetup/decline/', views.decline_meetup_view, name='decline_meetup'),
    path('orders/<str:pk>/messages/', views.send_order_message_view, name='order_messages'),
    path('orders/<str:pk>/prep/', views.set_prep_stage_view, name='set_prep_stage'),
    path('orders/<str:pk>/collected/', views.mark_collected_view, name='mark_collected'),
    path('orders/<str:pk>/complete/', views.complete_by_code_view, name='complete_by_code'),
    path('orders/<str:pk>/collection-nudge/', views.collection_nudge_view, name='collection_nudge'),

    # Payments & Payouts
    path('payments/initialize/', views.init_payment_view, name='init_payment'),
    path('payments/verify/', views.verify_payment_view, name='verify_payment'),
    path('payments/webhook/', views.paystack_webhook_view, name='paystack_webhook'),
    path('payouts/', views.payouts_ledger_view, name='payouts_ledger'),
    path('payouts/batches/', views.payout_batches_view, name='payout_batches'),

    # Reviews & Moderation
    path('reviews/', views.create_review_view, name='create_review'),
    path('admin/reviews/queue/', views.moderation_queue_view, name='moderation_queue'),
    path('admin/reviews/<str:orderId>/moderate/', views.moderate_review_view, name='moderate_review'),

    # Vendor compliance
    path('vendor/apply/', views.vendor_apply_view, name='vendor_apply'),
    path('vendor/activate/', views.vendor_activate_view, name='vendor_activate'),
    path('vendor/compliance/', views.vendor_compliance_view, name='vendor_compliance'),
    path('admin/compliance/', views.admin_compliance_view, name='admin_compliance'),

    # Support Cases
    path('support/cases/', views.support_cases_view, name='support_cases'),
    path('support/cases/<str:code>/resolve/', views.support_case_resolve_view, name='support_case_resolve'),

    # Admin Management
    path('admin/vendors/', views.admin_vendors_view, name='admin_vendors'),
    path('admin/vendors/<str:pk>/', views.admin_vendor_detail_view, name='admin_vendor_detail'),
    path('admin/users/', views.admin_users_view, name='admin_users'),
    path('admin/users/<str:pk>/', views.admin_user_detail_view, name='admin_user_detail'),
    path('admin/audit/', views.admin_audit_view, name='admin_audit'),
    path('admin/conversations/', views.admin_conversations_view, name='admin_conversations'),
    path('admin/conversations/<str:pk>/messages/', views.admin_conversation_messages_view, name='admin_conversation_messages'),
    path('admin/security/failed-logins/', views.admin_failed_logins_view, name='admin_failed_logins'),

    # Notifications & Analytics
    path('notifications/subscribe/', views.subscribe_push_view, name='subscribe_push'),
    path('notifications/unsubscribe/', views.unsubscribe_push_view, name='unsubscribe_push'),
    path('analytics/events/', views.analytics_event_view, name='analytics_events'),
]
