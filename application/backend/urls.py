from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.urls import path, include
from django.conf.urls.static import static
from django.conf import settings




urlpatterns = [
    path('', views.home, name='homepage'),
    path('contact/submit/', views.contact_submit, name='contact_submit'),
    path('login/', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),

    path('password/reset/', views.forgot_password, name='forgot_password'),
    path('password/reset/verify/', views.password_reset_verify, name='password_reset_verify'),
    path('password/reset/resend/', views.resend_verification_code, name='resend_verification_code'),

    path('term/', views.term, name='term'),


    path('accounts/', include('allauth.urls')),
    path('social-auth/', include('social_django.urls', namespace='social')),
    path('social/signup/', views.social_signup_complete, name='social_signup_complete'),
    path('social/redirect/', views.redirect_after_social_login, name='redirect_after_social_login'),


    path('logout/', views.user_logout, name='logout'),
    
    # Dashboard URLs
    path('dashboard/athlete/', views.athlete_dashboard, name='athlete_dashboard'),
    path('dashboard/psychologist/', views.psychologist_dashboard, name='psychologist_dashboard'),
    path('dashboard/coach/', views.coach_dashboard, name='coach_dashboard'),
    path('dashboard/nutritionist/', views.nutritionist_dashboard, name='nutritionist_dashboard'),
    path('dashboard/admin/', views.admin_dashboard, name='admin_dashboard'),

    # admin urls
    path('admin_user/', views.admin_crud, name='admin_user'),
    
    # Admin API endpoints for user management
    path('admin_user/', views.admin_crud, name='admin_get_users'),
    # Detailed user view, creation, updating
    path('crud/users/<int:user_id>/', views.admin_get_user, name='admin_get_user'),
    path('crud/users/create/', views.admin_create_user, name='admin_create_user'),
    path('crud/users/<int:user_id>/update/', views.admin_update_user, name='admin_update_user'),
    path('crud/users/<int:user_id>/delete/', views.admin_delete_user, name='admin_delete_user'),  # Added delete URL
    # Professional verification
    path('crud/users/<int:user_id>/verify/', views.admin_verify_professional, name='admin_verify_professional'),
    # Account status management
    path('crud/users/<int:user_id>/status/', views.admin_update_account_status, name='admin_update_account_status'),
    # Statistics and reporting
    path('crud/statistics/', views.admin_get_statistics, name='admin_get_statistics'),
    # Data export
    path('crud/users/export/', views.admin_export_users, name='admin_export_users'),
    path('contact_management/', views.contact_management, name='contact_management'),


## error
    path('complete-profile/athlete/', views.complete_athlete_profile, name='complete_athlete_profile'),
    path('payment/status/<str:reference>/', views.payment_status, name='payment_status'),
    path('payment/receipt/download/', views.download_receipt, name='download_receipt'),
    path('check-profile-completion/athlete/', views.check_profile_completion, name='check_profile_completion'),

## athlete panel

    path('Appointments/', views.Appointments, name='Appointments'),
    path('Assessments/', views.Assessments, name='Assessments'),
    path('WellnessResources/', views.WellnessResources, name='WellnessResources'),
    path('AthleteCommunity/', views.AthleteCommunity, name='AthleteCommunity'),
    path('ProgressTracker/', views.ProgressTracker, name='ProgressTracker'),





]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)