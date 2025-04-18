from functools import wraps
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login as auth_login, authenticate, logout
from django.contrib.auth.decorators import login_required
from .forms import ContactForm, NewsletterForm, UserRegistrationForm
from .models import ContactMessage, NewsletterSubscriber, User
import uuid
import yagmail
import os
from datetime import datetime, timedelta, timezone
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib.auth import login as auth_login
from django.contrib import messages
from .forms import UserRegistrationForm, SocialSignupForm
from .models import User
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages
from django.db.models import Count, Q
from .models import User
import json
from datetime import datetime, timedelta
from django.db.models.functions import TruncMonth
from django.utils import timezone
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q, Count
from django.db.models.functions import TruncMonth
from datetime import datetime, timedelta
from django.utils import timezone
import json

# Get your User model
User = get_user_model()

from django.db import models

def home(request):
    newsletter_form = NewsletterForm()
    
    if request.method == 'POST':
        # Handle newsletter subscription
        newsletter_form = NewsletterForm(request.POST)
        if newsletter_form.is_valid():
            email = newsletter_form.cleaned_data['email']
            # Check if email already exists
            if not NewsletterSubscriber.objects.filter(email=email).exists():
                newsletter_form.save()
                messages.success(request, 'Thank you for subscribing to our newsletter!')
            else:
                messages.info(request, 'This email is already subscribed to our newsletter.')
            return redirect('homepage')
    
    return render(request, 'LandingPage/HomePage.html', {
        'newsletter_form': newsletter_form
    })

def term(request):
    return render(request, 'LandingPage/term.html')


def contact_submit(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Thank you for your message. We will get back to you soon!')
            return redirect('homepage')
        else:
            # If form is invalid, we'll handle the error in the template
            pass
    return redirect('homepage')

def user_login(request):
    if request.user.is_authenticated:
        return redirect_to_dashboard(request.user)
        
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        remember_me = request.POST.get('remember-me')
        
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            auth_login(request, user)
            
            # Set session expiry based on remember-me checkbox
            if not remember_me:
                request.session.set_expiry(3600)  # 1 hour in seconds
                request.session['last_activity'] = timezone.now().timestamp()
            
            messages.success(request, f'Welcome back, {user.first_name}!')
            return redirect_to_dashboard(user)
        else:
            messages.error(request, 'Invalid email or password. Please try again.')
    
    return render(request, 'Authentication/Login.html')


def redirect_to_dashboard(user):
    """Helper function to redirect users to their appropriate dashboard"""
    if user.user_type == 'athlete':
        return redirect('athlete_dashboard')
    elif user.user_type == 'psychologist':
        return redirect('psychologist_dashboard')
    elif user.user_type == 'coach':
        return redirect('coach_dashboard')
    elif user.user_type == 'nutritionist':
        return redirect('nutritionist_dashboard')
    elif user.user_type == 'admin' or user.is_staff:
        return redirect('admin_dashboard')
    else:
        # Default fallback
        return redirect('homepage')

def register(request):
    if request.user.is_authenticated:
        # If user is already logged in, redirect to appropriate dashboard
        return redirect_to_dashboard(request.user)
        
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.username = form.cleaned_data['email']  # Use email as username
            user.save()
            
            # Log the user in after registration - Fix: Specify the backend
            user.backend = 'django.contrib.auth.backends.ModelBackend'  # Specify the backend
            auth_login(request, user)
            
            messages.success(request, f'Welcome, {user.first_name}! Your registration was successful.')
            return redirect_to_dashboard(user)
    else:
        form = UserRegistrationForm(initial={'user_type': 'athlete'})  # Default to athlete
    
    return render(request, 'Authentication/Register.html', {'form': form})
class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    verification_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    
    def is_valid(self):
        now = datetime.now().replace(tzinfo=self.expires_at.tzinfo)
        return not self.is_used and now < self.expires_at
    
    def __str__(self):
        return f"Reset token for {self.user.email}"

# Helper functions
def generate_verification_code():
    """Generate a 6-digit verification code"""
    import random
    return ''.join(random.choices('0123456789', k=6))

def send_reset_email(user_email, verification_code, reset_link):
    """Send password reset email using yagmail"""
    try:
        # Configure email settings (you should set these in your Django settings.py)
        email_user = settings.EMAIL_HOST_USER
        email_password = settings.EMAIL_HOST_PASSWORD
        
        # Email subject and body
        subject = "Password Reset Request - Mental Health Platform Cameroon"
        
        # HTML body with styling
        html_content = f"""
        <div style="font-family: 'Arial', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px; background-color: #f9f9f9;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #0284c7; margin-bottom: 10px;">Password Reset</h1>
                <p style="color: #555555; font-size: 16px;">Mental Health Platform Cameroon</p>
            </div>
            
            <div style="background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px;">
                <p style="margin-bottom: 15px; font-size: 15px; line-height: 1.5; color: #333333;">
                    We received a request to reset your password. To complete the process, please use the verification code below:
                </p>
                
                <div style="text-align: center; margin: 25px 0;">
                    <div style="font-family: monospace; font-size: 24px; letter-spacing: 5px; background-color: #f0f9ff; padding: 15px; border-radius: 8px; display: inline-block; font-weight: bold; color: #0284c7; border: 1px dashed #90cdf4;">
                        {verification_code}
                    </div>
                </div>
                
                <p style="margin-bottom: 15px; font-size: 15px; line-height: 1.5; color: #333333;">
                    Alternatively, you can click the button below to reset your password directly:
                </p>
                
                <div style="text-align: center; margin: 25px 0;">
                    <a href="{reset_link}" style="background-color: #0284c7; color: white; text-decoration: none; padding: 12px 25px; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
                </div>
                
                <p style="margin-bottom: 15px; font-size: 14px; line-height: 1.5; color: #666666;">
                    If you didn't request a password reset, please ignore this email or contact support if you have concerns.
                </p>
                
                <p style="font-size: 14px; color: #777777;">
                    This code will expire in 5 minutes for security reasons.
                </p>
            </div>
            
            <div style="text-align: center; margin-top: 20px; color: #888888; font-size: 13px;">
                <p>Mental Health Platform for Cameroonian Combat Athletes</p>
                <p>&copy; 2025 All rights reserved.</p>
            </div>
        </div>
        """
        
        # Initialize yagmail SMTP
        yag = yagmail.SMTP(email_user, email_password)
        
        # Send email
        yag.send(
            to=user_email,
            subject=subject,
            contents=html_content
        )
        
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# forgot pwd functions
def forgot_password(request):
    """Handle password reset request (Step 1)"""
    if request.method == 'POST':
        email = request.POST.get('email')
        
        try:
            user = User.objects.get(email=email)
            
            # Generate verification code
            verification_code = generate_verification_code()
            
            # Set expiration time (5 minutes from now)
            expiry_time = datetime.now() + timedelta(minutes=5)
            
            # Create or update reset token
            reset_token, created = PasswordResetToken.objects.update_or_create(
                user=user,
                defaults={
                    'verification_code': verification_code,
                    'expires_at': expiry_time,
                    'is_used': False
                }
            )
            
            # Generate reset link
            reset_link = request.build_absolute_uri(
                f"{reverse('password_reset_verify')}?token={reset_token.token}&email={email}"
            )
            
            # Send email with reset instructions
            email_sent = send_reset_email(email, verification_code, reset_link)
            
            if email_sent:
                messages.success(request, "A password reset code has been sent to your email.")
                return redirect(f"{reverse('password_reset_verify')}?email={email}")
            else:
                messages.error(request, "Failed to send reset email. Please try again.")
        except ObjectDoesNotExist:
            # Don't reveal whether a user exists for security reasons
            messages.info(request, "If an account with this email exists, a reset link has been sent.")
            # Delay response to prevent timing attacks
            import time
            time.sleep(1)
        except Exception as e:
            messages.error(request, "An error occurred. Please try again later.")
            print(f"Password reset error: {e}")
    
    return render(request, 'Authentication/Forgot_password.html')

def password_reset_verify(request):
    """Handle verification code and password reset (Step 2 and 3)"""
    email = request.GET.get('email', '')
    token_uuid = request.GET.get('token', '')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        verification_code = request.POST.get('verificationCode')
        new_password = request.POST.get('newPassword')
        confirm_password = request.POST.get('confirmPassword')
        
        if not all([email, verification_code, new_password, confirm_password]):
            messages.error(request, "All fields are required.")
            return render(request, 'Authentication/Forgot_password.html', {'email': email})
        
        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'Authentication/Forgot_password.html', {'email': email})
        
        try:
            user = User.objects.get(email=email)
            token = PasswordResetToken.objects.filter(
                user=user,
                verification_code=verification_code,
                is_used=False
            ).order_by('-created_at').first()
            
            if not token or not token.is_valid():
                messages.error(request, "Invalid or expired verification code.")
                return render(request, 'Authentication/Forgot_password.html', {'email': email})
            
            # Update password
            user.password = make_password(new_password)
            user.save()
            
            # Mark token as used
            token.is_used = True
            token.save()
            
            messages.success(request, "Your password has been successfully reset. You can now log in with your new password.")
            return redirect('login')
            
        except ObjectDoesNotExist:
            messages.error(request, "Invalid email or verification code.")
        except Exception as e:
            messages.error(request, "An error occurred. Please try again later.")
            print(f"Password reset verification error: {e}")
    
    return render(request, 'Authentication/Forgot_password.html', {'email': email})

def resend_verification_code(request):
    """API endpoint to resend verification code"""
    if request.method == 'POST':
        email = request.POST.get('email')
        
        try:
            user = User.objects.get(email=email)
            
            # Generate new verification code
            verification_code = generate_verification_code()
            
            # Set expiration time (5 minutes from now)
            expiry_time = datetime.now() + timedelta(minutes=5)
            
            # Create or update reset token
            reset_token, created = PasswordResetToken.objects.update_or_create(
                user=user,
                defaults={
                    'verification_code': verification_code,
                    'expires_at': expiry_time,
                    'is_used': False
                }
            )
            
            # Generate reset link
            reset_link = request.build_absolute_uri(
                f"{reverse('password_reset_verify')}?token={reset_token.token}&email={email}"
            )
            
            # Send email with reset instructions
            email_sent = send_reset_email(email, verification_code, reset_link)
            
            if email_sent:
                return JsonResponse({'status': 'success', 'message': 'Verification code resent.'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Failed to send reset email.'})
                
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': 'An error occurred.'})
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

@login_required
def user_logout(request):
    # Get the user's name before logging out
    user_name = request.user.first_name
    
    # Log the user out
    logout(request)
    
    # Clear any session data
    request.session.flush()
    
    # Set a success message
    messages.success(request, f'Goodbye, {user_name}! You have been successfully logged out.')
    
    # Redirect to login page
    return redirect('login')

def social_signup_complete(request):
    if not request.user.is_authenticated or not request.user.social_provider:
        return redirect('register')
    
    if request.method == 'POST':
        form = SocialSignupForm(request.POST)
        if form.is_valid():
            user = request.user
            user.user_type = form.cleaned_data['user_type']
            user.sport = form.cleaned_data.get('sport')
            user.level = form.cleaned_data.get('level')
            user.qualifications = form.cleaned_data.get('qualifications')
            user.years_experience = form.cleaned_data.get('years_experience')
            user.terms_accepted = True
            user.save()
            
            messages.success(request, "Your account has been successfully created!")
            return redirect_to_dashboard(user)
    else:
        form = SocialSignupForm()
    
    return render(request, 'Authentication/social_signup_complete.html', {
        'form': form,
        'user': request.user
    })

def redirect_after_social_login(request):
    if not request.user.is_authenticated:
        return redirect('login')
    
    if request.user.user_type:  # If user has already completed profile
        return redirect_to_dashboard(request.user)
    else:
        return redirect('social_signup_complete')

def redirect_to_dashboard(user):
    """Helper function to redirect users to their appropriate dashboard"""
    if user.user_type == 'athlete':
        return redirect('athlete_dashboard')
    elif user.user_type == 'psychologist':
        return redirect('psychologist_dashboard')
    elif user.user_type == 'coach':
        return redirect('coach_dashboard')
    elif user.user_type == 'nutritionist':
        return redirect('nutritionist_dashboard')
    elif user.user_type == 'admin' or user.is_staff:
        return redirect('admin_dashboard')
    else:
        return redirect('homepage')


# Placeholder dashboard views - create actual views based on your needs

@login_required
def psychologist_dashboard(request):
    return render(request, 'Dashboards/Psychologist/PsychologistPanel.html')

@login_required
def coach_dashboard(request):
    return render(request, 'Dashboards/Coach/CoachPanel.html')

@login_required
def nutritionist_dashboard(request):
    return render(request, 'Dashboards/Nutritionist/NutritionistPanel.html')

@login_required
def admin_dashboard(request):
    return render(request, 'Dashboards/Admin/AdminPanel.html')

# admin user management

def is_admin(user):
    return user.is_staff or user.user_type == 'admin'

@login_required
@user_passes_test(is_admin)
def admin_crud(request):
    # Get statistics for dashboard
    statistics = get_user_statistics()
    
    # Get all users for listing in the admin panel with filters
    users = User.objects.all().order_by('-date_joined')
    
    # Apply filters if provided
    user_type = request.GET.get('user_type')
    sport = request.GET.get('sport')
    level = request.GET.get('level')
    account_status = request.GET.get('account_status')
    payment_status = request.GET.get('payment_status')
    is_verified = request.GET.get('is_verified')
    search_query = request.GET.get('search', '')
    
    if user_type:
        users = users.filter(user_type=user_type)
    
    if sport:
        users = users.filter(sport=sport)
    
    if level:
        users = users.filter(level=level)
    
    if account_status:
        users = users.filter(account_status=account_status)
    
    if payment_status:
        users = users.filter(payment_status=payment_status)
    
    if is_verified:
        if is_verified == 'verified':
            users = users.filter(is_verified_professional=True)
        else:
            users = users.filter(is_verified_professional=False)
    
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) | 
            Q(email__icontains=search_query) |
            Q(mobile_number__icontains=search_query) |
            Q(town__icontains=search_query) |
            Q(license_number__icontains=search_query)
        )
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(users, 10)  # Show 10 users per page
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)
    
    # User growth data for chart
    user_growth = get_user_growth_data()
    
    # Get distinct values for filter dropdowns
    sport_choices = User.SPORT_CHOICES
    level_choices = User.LEVEL_CHOICES
    user_type_choices = User.USER_TYPE_CHOICES
    account_status_choices = User.ACCOUNT_STATUS_CHOICES
    payment_status_choices = (
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
        ('expired', 'Expired'),
    )
    
    context = {
        'users': users_page,
        'statistics': statistics,
        'sport_choices': sport_choices,
        'level_choices': level_choices,
        'user_type_choices': user_type_choices,
        'account_status_choices': account_status_choices,
        'payment_status_choices': payment_status_choices,
        'user_growth_months': json.dumps(user_growth['months']),
        'user_growth_data': json.dumps(user_growth['data']),
        'selected_filters': {
            'user_type': user_type,
            'sport': sport,
            'level': level,
            'account_status': account_status,
            'payment_status': payment_status,
            'is_verified': is_verified,
            'search': search_query
        }
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_user.html', context)

def get_user_statistics():
    """Helper function to get user statistics"""
    statistics = {
        'total_users': User.objects.count(),
        'athlete_count': User.objects.filter(user_type='athlete').count(),
        'professional_count': User.objects.filter(user_type__in=['psychologist', 'coach', 'nutritionist']).count(),
        'psychologist_count': User.objects.filter(user_type='psychologist').count(),
        'coach_count': User.objects.filter(user_type='coach').count(),
        'nutritionist_count': User.objects.filter(user_type='nutritionist').count(),
        'admin_count': User.objects.filter(user_type='admin').count(),
        
        # Account status counts
        'pending_count': User.objects.filter(account_status='pending').count(),
        'active_count': User.objects.filter(account_status='active').count(),
        'blocked_count': User.objects.filter(account_status='blocked').count(),
        'suspended_count': User.objects.filter(account_status='suspended').count(),
        
        # Payment status counts
        'payment_pending_count': User.objects.filter(payment_status='pending').count(),
        'payment_paid_count': User.objects.filter(payment_status='paid').count(),
        'payment_failed_count': User.objects.filter(payment_status='failed').count(),
        'payment_expired_count': User.objects.filter(payment_status='expired').count(),
        
        # Verification status
        'verified_professionals': User.objects.filter(is_verified_professional=True).count(),
        'unverified_professionals': User.objects.filter(
            user_type__in=['psychologist', 'coach', 'nutritionist'],
            is_verified_professional=False
        ).count(),
        
        # Sport counts
        'boxing_count': User.objects.filter(sport='boxing').count(),
        'wrestling_count': User.objects.filter(sport='wrestling').count(),
        'judo_count': User.objects.filter(sport='judo').count(),
        'karate_count': User.objects.filter(sport='karate').count(),
        'taekwondo_count': User.objects.filter(sport='taekwondo').count(),
        'mma_count': User.objects.filter(sport='mma').count(),
        'other_sport_count': User.objects.filter(sport='other').count(),
        
        # Level counts
        'amateur_count': User.objects.filter(level='amateur').count(),
        'semipro_count': User.objects.filter(level='semi-pro').count(),
        'professional_count': User.objects.filter(level='professional').count(),
        'elite_count': User.objects.filter(level='elite').count(),
        
        # New users statistics
        'new_users_30_days': User.objects.filter(date_joined__gte=datetime.now() - timedelta(days=30)).count(),
        'new_users_7_days': User.objects.filter(date_joined__gte=datetime.now() - timedelta(days=7)).count(),
        'new_users_today': User.objects.filter(date_joined__date=datetime.now().date()).count(),
    }
    
    return statistics

@login_required
@user_passes_test(is_admin)
def admin_get_user(request, user_id):
    """View a single user's details"""
    user = get_object_or_404(User, id=user_id)
    
    # Calculate subscription status
    subscription_active = user.is_subscription_active()
    
    # Get payment history if we had a Payment model
    # payments = Payment.objects.filter(user=user).order_by('-payment_date')
    
    context = {
        'user': user,
        'subscription_active': subscription_active,
        'account_status_choices': User.ACCOUNT_STATUS_CHOICES,
        # 'payments': payments
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_user_detail.html', context)

@login_required
@user_passes_test(is_admin)
def admin_create_user(request):
    """Create a new user"""
    if request.method == 'POST':
        try:
            # Process form data
            email = request.POST.get('email')
            first_name = request.POST.get('first_name')
            last_name = request.POST.get('last_name')
            user_type = request.POST.get('user_type')
            password = request.POST.get('password', User.objects.make_random_password())
            
            # Check if email already exists
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already exists')
                return redirect('admin_create_user')
            
            # Create user with basic fields
            new_user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                user_type=user_type,
                terms_accepted=True
            )
            
            # Update fields based on user type
            new_user.sport = request.POST.get('sport')
            new_user.level = request.POST.get('level')
            new_user.town = request.POST.get('town')
            new_user.quartier = request.POST.get('quartier')
            new_user.mobile_number = request.POST.get('mobile_number')
            new_user.account_status = request.POST.get('account_status', 'pending')
            
            # Professional-specific fields
            if user_type in ['psychologist', 'coach', 'nutritionist']:
                new_user.qualifications = request.POST.get('qualifications')
                new_user.years_experience = request.POST.get('years_experience')
                new_user.license_number = request.POST.get('license_number')
                new_user.is_verified_professional = request.POST.get('is_verified_professional') == 'on'
                
                if new_user.is_verified_professional:
                    new_user.date_verified = timezone.now()
                    
                # Handle file uploads if present
                if 'certification_document' in request.FILES:
                    new_user.certification_document = request.FILES['certification_document']
                
                if 'cv_document' in request.FILES:
                    new_user.cv_document = request.FILES['cv_document']
                
                if 'additional_documents' in request.FILES:
                    new_user.additional_documents = request.FILES['additional_documents']
                
                new_user.verification_notes = request.POST.get('verification_notes')
            
            # Handle profile image if present
            if 'profile_image' in request.FILES:
                new_user.profile_image = request.FILES['profile_image']
            
            # Payment related fields
            payment_status = request.POST.get('payment_status')
            if payment_status:
                new_user.payment_status = payment_status
                
                if payment_status == 'paid':
                    new_user.last_payment_date = timezone.now()
                    new_user.next_payment_due = timezone.now() + timezone.timedelta(days=30)
            
            new_user.save()
            
            messages.success(request, f'User {first_name} {last_name} created successfully!')
            return redirect('admin_get_users')
            
        except Exception as e:
            messages.error(request, f'Error creating user: {str(e)}')
            return redirect('admin_create_user')
    
    # GET request - show create form with all choices from model
    context = {
        'user_type_choices': User.USER_TYPE_CHOICES,
        'sport_choices': User.SPORT_CHOICES,
        'level_choices': User.LEVEL_CHOICES,
        'account_status_choices': User.ACCOUNT_STATUS_CHOICES,
        'payment_status_choices': (
            ('pending', 'Pending'),
            ('paid', 'Paid'),
            ('failed', 'Failed'),
            ('expired', 'Expired'),
        )
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_create_user.html', context)

@login_required
@user_passes_test(is_admin)
def admin_update_user(request, user_id):
    """Update an existing user"""
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        try:
            # Process form data for basic fields
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.user_type = request.POST.get('user_type', user.user_type)
            
            # Check if email changed and is unique
            new_email = request.POST.get('email')
            if new_email != user.email and User.objects.filter(email=new_email).exists():
                messages.error(request, 'Email already in use by another account')
                return redirect('admin_update_user', user_id=user_id)
            
            user.email = new_email
            user.username = new_email  # Keep username and email in sync
            
            # Update common fields
            user.sport = request.POST.get('sport', user.sport)
            user.level = request.POST.get('level', user.level)
            user.town = request.POST.get('town', user.town)
            user.quartier = request.POST.get('quartier', user.quartier)
            user.mobile_number = request.POST.get('mobile_number', user.mobile_number)
            user.account_status = request.POST.get('account_status', user.account_status)
            
            # Professional-specific fields
            if user.user_type in ['psychologist', 'coach', 'nutritionist']:
                user.qualifications = request.POST.get('qualifications', user.qualifications)
                user.years_experience = request.POST.get('years_experience', user.years_experience)
                user.license_number = request.POST.get('license_number', user.license_number)
                
                was_verified = user.is_verified_professional
                user.is_verified_professional = request.POST.get('is_verified_professional') == 'on'
                
                # Set verification date if newly verified
                if not was_verified and user.is_verified_professional:
                    user.date_verified = timezone.now()
                
                # Handle file uploads if present
                if 'certification_document' in request.FILES:
                    user.certification_document = request.FILES['certification_document']
                
                if 'cv_document' in request.FILES:
                    user.cv_document = request.FILES['cv_document']
                
                if 'additional_documents' in request.FILES:
                    user.additional_documents = request.FILES['additional_documents']
                
                user.verification_notes = request.POST.get('verification_notes', user.verification_notes)
            
            # Handle profile image if present
            if 'profile_image' in request.FILES:
                user.profile_image = request.FILES['profile_image']
            
            # Payment related fields
            payment_status = request.POST.get('payment_status')
            if payment_status and payment_status != user.payment_status:
                user.payment_status = payment_status
                
                if payment_status == 'paid' and (not user.last_payment_date or user.payment_status != 'paid'):
                    user.last_payment_date = timezone.now()
                    user.next_payment_due = timezone.now() + timezone.timedelta(days=30)
            
            # Manually set membership fee if provided
            if request.POST.get('membership_fee'):
                user.membership_fee = request.POST.get('membership_fee')
            
            # Handle password update if provided
            password = request.POST.get('password')
            if password:
                user.set_password(password)
            
            user.save()
            messages.success(request, f'User {user.get_full_name()} updated successfully!')
            return redirect('admin_get_users')
            
        except Exception as e:
            messages.error(request, f'Error updating user: {str(e)}')
            return redirect('admin_update_user', user_id=user_id)
    
    # GET request - show update form with choices from model
    context = {
        'user': user,
        'user_type_choices': User.USER_TYPE_CHOICES,
        'sport_choices': User.SPORT_CHOICES,
        'level_choices': User.LEVEL_CHOICES,
        'account_status_choices': User.ACCOUNT_STATUS_CHOICES,
        'payment_status_choices': (
            ('pending', 'Pending'),
            ('paid', 'Paid'),
            ('failed', 'Failed'),
            ('expired', 'Expired'),
        )
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_update_user.html', context)

@login_required
@user_passes_test(is_admin)
def admin_verify_professional(request, user_id):
    """Verify a professional user"""
    user = get_object_or_404(User, id=user_id)
    
    if user.user_type not in ['psychologist', 'coach', 'nutritionist']:
        messages.error(request, f'User {user.get_full_name()} is not a professional account')
        return redirect('admin_get_user', user_id=user_id)
    
    user.is_verified_professional = True
    user.date_verified = timezone.now()
    user.account_status = 'active'
    user.save()
    
    # Send verification email to user
    # send_verification_email(user)
    
    messages.success(request, f'Professional {user.get_full_name()} has been verified successfully')
    return redirect('admin_get_user', user_id=user_id)

@login_required
@user_passes_test(is_admin)
def admin_update_account_status(request, user_id):
    """Update account status"""
    if request.method == 'POST':
        user = get_object_or_404(User, id=user_id)
        new_status = request.POST.get('account_status')
        
        if new_status in dict(User.ACCOUNT_STATUS_CHOICES):
            user.account_status = new_status
            user.save()
            messages.success(request, f'Account status for {user.get_full_name()} updated to {new_status}')
        else:
            messages.error(request, 'Invalid account status')
        
        return redirect('admin_get_user', user_id=user_id)
    
    return redirect('admin_get_users')

@login_required
@user_passes_test(is_admin)
def admin_get_statistics(request):
    """View detailed statistics"""
    statistics = get_user_statistics()
    
    # Get more detailed statistics
    # Get new users by month for the last 6 months
    six_months_ago = datetime.now() - timedelta(days=180)
    
    monthly_signups = (
        User.objects.filter(date_joined__gte=six_months_ago)
        .annotate(month=TruncMonth('date_joined'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    
    # Get athletes by level
    athletes_by_level = User.objects.filter(
        user_type='athlete'
    ).values('level').annotate(count=Count('id'))
    
    # Get professionals by verification status
    professionals_by_verification = User.objects.filter(
        user_type__in=['psychologist', 'coach', 'nutritionist']
    ).values('user_type', 'is_verified_professional').annotate(count=Count('id'))
    
    # Get users by payment status
    users_by_payment = User.objects.values('payment_status').annotate(count=Count('id'))
    
    # Get users by account status
    users_by_account_status = User.objects.values('account_status').annotate(count=Count('id'))
    
    # Get users by town
    users_by_town = User.objects.exclude(town__isnull=True).exclude(town='').values('town').annotate(count=Count('id')).order_by('-count')[:10]
    
    user_growth = get_user_growth_data()
    
    context = {
        'statistics': statistics,
        'monthly_signups': list(monthly_signups),
        'athletes_by_level': list(athletes_by_level),
        'professionals_by_verification': list(professionals_by_verification),
        'users_by_payment': list(users_by_payment),
        'users_by_account_status': list(users_by_account_status),
        'users_by_town': list(users_by_town),
        'user_growth_months': json.dumps(user_growth['months']),
        'user_growth_data': json.dumps(user_growth['data'])
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_statistics.html', context)

@login_required
@user_passes_test(is_admin)
def admin_export_users(request):
    """Export users to CSV/Excel"""
    import csv
    from django.http import HttpResponse
    
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="users_export.csv"'
    
    writer = csv.writer(response)
    # Header row
    writer.writerow([
        'ID', 'Email', 'First Name', 'Last Name', 'User Type', 
        'Date Joined', 'Sport', 'Level', 'Town', 'Quartier',
        'Mobile Number', 'Account Status', 'Payment Status',
        'Is Verified Professional', 'Qualifications', 'Years Experience',
        'License Number', 'Last Payment Date', 'Next Payment Due',
        'Membership Fee'
    ])
    
    # Apply filters from request if any
    users = User.objects.all().order_by('-date_joined')
    
    # Get filter parameters
    user_type = request.GET.get('user_type')
    if user_type:
        users = users.filter(user_type=user_type)
    
    # Add additional filters as needed
    # [...]
    
    # Export data
    for user in users:
        writer.writerow([
            user.id, user.email, user.first_name, user.last_name,
            user.get_user_type_display(), user.date_joined, 
            user.get_sport_display() if user.sport else '',
            user.get_level_display() if user.level else '',
            user.town or '', user.quartier or '',
            user.mobile_number or '', user.get_account_status_display(),
            user.payment_status,
            'Yes' if user.is_verified_professional else 'No',
            user.qualifications or '', user.years_experience or '',
            user.license_number or '',
            user.last_payment_date or '', user.next_payment_due or '',
            user.membership_fee
        ])
    
    return response

@login_required
@user_passes_test(is_admin)
def admin_delete_user(request, user_id):
    """Delete a user"""
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        user_name = user.get_full_name()
        user.delete()
        messages.success(request, f'User {user_name} has been deleted successfully')
        return redirect('admin_get_users')
    
    # If GET request, show confirmation page
    return render(request, 'Dashboards/Admin/User Management/admin_user.html', {'user': user})

def get_user_growth_data():
    """Helper function to get user growth data for charts"""
    from django.db.models.functions import TruncMonth
    from django.db.models import Count
    from datetime import datetime, timedelta
    
    # Get data for the last 12 months
    twelve_months_ago = datetime.now() - timedelta(days=365)
    
    # Get monthly signups
    monthly_data = (
        User.objects
        .filter(date_joined__gte=twelve_months_ago)
        .annotate(month=TruncMonth('date_joined'))
        .values('month')
        .annotate(count=Count('id'))
        .order_by('month')
    )
    
    # Prepare data for chart
    months = []
    counts = []
    
    for entry in monthly_data:
        months.append(entry['month'].strftime('%b %Y'))
        counts.append(entry['count'])
    
    return {
        'months': months,
        'data': counts
    }

#admin contact management and update this part for production
@login_required
def contact_management(request):
    # Handle contact messages
    if request.method == 'POST':
        # Reply to a contact message
        if 'reply_message' in request.POST:
            message_id = request.POST.get('message_id')
            reply_content = request.POST.get('reply_content')
            
            try:
                message = ContactMessage.objects.get(id=message_id)
                
                # Send email reply using yagmail
                import yagmail
                
                # Configure your email credentials - should be in settings.py in production
                sender_email = "yvangodimomo@gmail.com"
                sender_password = "pzls apph esje cgdl"  # Use environment variables in production
                
                # Initialize yagmail
                yag = yagmail.SMTP(sender_email, sender_password)
                
                # Send the email
                yag.send(
                    to=message.email,
                    subject=f"Re: {message.subject}",
                    contents=reply_content
                )
                
                messages.success(request, f"Reply sent to {message.email}")
                
            except ContactMessage.DoesNotExist:
                messages.error(request, "Message not found")
            except Exception as e:
                messages.error(request, f"Failed to send email: {str(e)}")
                
            return redirect('contact_management')
            
        # Delete a contact message
        elif 'delete_message' in request.POST:
            message_id = request.POST.get('message_id')
            
            try:
                message = ContactMessage.objects.get(id=message_id)
                message.delete()
                messages.success(request, "Message deleted successfully")
            except ContactMessage.DoesNotExist:
                messages.error(request, "Message not found")
                
            return redirect('contact_management')
            
        # Add a newsletter subscriber
        elif 'add_subscriber' in request.POST:
            email = request.POST.get('subscriber_email')
            is_active = request.POST.get('subscriber_active') == 'on'
            
            try:
                subscriber, created = NewsletterSubscriber.objects.get_or_create(
                    email=email,
                    defaults={'is_active': is_active}
                )
                
                if not created:
                    subscriber.is_active = is_active
                    subscriber.save()
                    messages.success(request, f"Subscriber {email} updated")
                else:
                    messages.success(request, f"Subscriber {email} added successfully")
                    
            except Exception as e:
                messages.error(request, f"Failed to add subscriber: {str(e)}")
                
            return redirect('contact_management')
            
        # Delete a subscriber
        elif 'delete_subscriber' in request.POST:
            subscriber_id = request.POST.get('subscriber_id')
            
            try:
                subscriber = NewsletterSubscriber.objects.get(id=subscriber_id)
                subscriber.delete()
                messages.success(request, "Subscriber removed successfully")
            except NewsletterSubscriber.DoesNotExist:
                messages.error(request, "Subscriber not found")
                
            return redirect('contact_management')
            
        # Toggle subscriber active status
        elif 'toggle_subscriber' in request.POST:
            subscriber_id = request.POST.get('subscriber_id')
            
            try:
                subscriber = NewsletterSubscriber.objects.get(id=subscriber_id)
                subscriber.is_active = not subscriber.is_active
                subscriber.save()
                status = "activated" if subscriber.is_active else "deactivated"
                messages.success(request, f"Subscriber {subscriber.email} {status}")
            except NewsletterSubscriber.DoesNotExist:
                messages.error(request, "Subscriber not found")
                
            return redirect('contact_management')
            
        # Send mass email to subscribers
        elif 'send_newsletter' in request.POST:
            subject = request.POST.get('email_subject')
            content = request.POST.get('email_content')
            
            # Get active subscribers
            subscribers = NewsletterSubscriber.objects.filter(is_active=True)
            
            if not subscribers.exists():
                messages.warning(request, "No active subscribers to send emails to")
                return redirect('contact_management')
                
            try:
                # Send email using yagmail
                import yagmail
                
                # Configure email credentials - should be in settings.py in production
                sender_email = "yvangodimomo@gmail.com"
                sender_password = "pzls apph esje cgdl"  # Use environment variables in production
                
                # Initialize yagmail
                yag = yagmail.SMTP(sender_email, sender_password)
                
                # Handle file attachments
                attachments = []
                if request.FILES.getlist('email_attachments'):
                    for file in request.FILES.getlist('email_attachments'):
                        # Save the file temporarily
                        import tempfile
                        import os
                        
                        temp = tempfile.NamedTemporaryFile(delete=False)
                        temp.write(file.read())
                        temp.close()
                        
                        attachments.append(temp.name)
                
                # Send to all active subscribers
                for subscriber in subscribers:
                    yag.send(
                        to=subscriber.email,
                        subject=subject,
                        contents=content,
                        attachments=attachments
                    )
                
                # Clean up temporary files
                for attachment in attachments:
                    os.unlink(attachment)
                    
                messages.success(request, f"Newsletter sent to {subscribers.count()} subscribers")
                
            except Exception as e:
                messages.error(request, f"Failed to send newsletter: {str(e)}")
                
            return redirect('contact_management')
            
    # Export contact emails
    elif 'export_contacts' in request.GET:
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="contact_emails.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Name', 'Email', 'Subject', 'Date'])
        
        contacts = ContactMessage.objects.all().order_by('-created_at')
        for contact in contacts:
            writer.writerow([
                contact.name, 
                contact.email, 
                contact.subject, 
                contact.created_at.strftime('%Y-%m-%d %H:%M')
            ])
            
        return response
        
    # Export subscriber emails
    elif 'export_subscribers' in request.GET:
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="newsletter_subscribers.csv"'
        
        writer = csv.writer(response)
        writer.writerow(['Email', 'Status', 'Subscribed Date'])
        
        subscribers = NewsletterSubscriber.objects.all().order_by('-subscribed_at')
        for subscriber in subscribers:
            writer.writerow([
                subscriber.email, 
                'Active' if subscriber.is_active else 'Inactive', 
                subscriber.subscribed_at.strftime('%Y-%m-%d %H:%M')
            ])
            
        return response
    
  # Get all contact messages and subscribers for template
    contact_messages = ContactMessage.objects.all().order_by('-created_at')
    subscribers = NewsletterSubscriber.objects.all().order_by('-subscribed_at')
    active_subscribers_count = NewsletterSubscriber.objects.filter(is_active=True).count()
    
    return render(request, 'Dashboards/Admin/management_contact/admin_management_contact.html', {
        'contact_messages': contact_messages,
        'subscribers': subscribers,
        'active_subscribers_count': active_subscribers_count,  # Pass the count to the template
    })



#Athlect panel
@login_required
def Appointments(request):
    return render(request, 'Dashboards/Athlete/Appointments/Appointments.html')

@login_required
def Assessments(request):
    return render(request, 'Dashboards/Athlete/ Mental Assessments/Assessments.html')

@login_required
def WellnessResources(request):
    return render(request, 'Dashboards/Athlete/ Wellness Resources/ WellnessResources.html')

@login_required
def AthleteCommunity(request):
    return render(request, 'Dashboards/Athlete/ Athlete Community/ AthleteCommunity.html')

@login_required
def ProgressTracker(request):
    return render(request, 'Dashboards/Athlete/ Progress Tracker/ ProgressTracker.html')



#athlete profile management

import uuid
import logging
import os
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
from django.utils import timezone
from django.http import HttpResponse
from django.db import transaction
from django.template.loader import render_to_string
from django.core.files.base import ContentFile
from campay.sdk import Client as CamPayClient
from io import BytesIO
from xhtml2pdf import pisa
from functools import wraps
from django.urls import reverse
from .forms import AthleteProfileForm
from .models import User
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from .forms import AthleteProfileForm
from .models import User

# Set up logger
logger = logging.getLogger(__name__)

# Initialize CamPay client
campay_client = CamPayClient({
    "app_username": settings.CAMPAY_USERNAME,
    "app_password": settings.CAMPAY_PASSWORD,
    "environment": settings.CAMPAY_ENVIRONMENT  # "TEST" or "PROD"
})


# Now, create a profile completion check decorator

def profile_completion_required(view_func):
    """
    Decorator to check if an athlete's profile is complete.
    If not, redirects to the profile completion page.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        # Only apply to athletes
        if request.user.is_authenticated and request.user.user_type == 'athlete':
            if not request.user.is_profile_complete():
                messages.warning(request, "Please complete your profile before accessing the dashboard.")
                return redirect('complete_athlete_profile')
        return view_func(request, *args, **kwargs)
    return _wrapped_view

# Set up logger
logger = logging.getLogger(__name__)

@login_required
@transaction.atomic
def complete_athlete_profile(request):
    # Redirect if user is not an athlete
    if request.user.user_type != 'athlete':
        messages.error(request, "This page is only for athletes.")
        return redirect_to_dashboard(request.user)
    
    # Redirect if profile is already complete
    if request.user.is_profile_complete():
        messages.info(request, "Your profile is already complete.")
        return redirect('athlete_dashboard')
    
    if request.method == 'POST':
        form = AthleteProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            try:
                # Save form data without committing
                athlete = form.save(commit=False)
                
                # Save mobile number from form
                mobile_number = form.cleaned_data.get('mobile_number')
                if not mobile_number:
                    messages.error(request, "Mobile number is required for payment.")
                    return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
                
                # Format phone number (add country code if needed)
                if not mobile_number.startswith('237'):
                    mobile_number = '237' + mobile_number
                
                logger.info(f"Formatted mobile number: {mobile_number}")
                athlete.mobile_number = mobile_number
                athlete.terms_accepted = request.POST.get('terms') == 'on'
                
                # Ensure profile image was uploaded
                if 'profile_image' not in request.FILES:
                    messages.error(request, "Profile image is required.")
                    return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
                
                # Save the athlete to update fields
                athlete.save()
                
                # Generate payment reference
                payment_reference = str(uuid.uuid4())
                logger.info(f"Generated payment reference: {payment_reference}")
                
                # Initialize CamPay client
                campay_client = CamPayClient({
                    "app_username": settings.CAMPAY_USERNAME,
                    "app_password": settings.CAMPAY_PASSWORD,
                    "environment": settings.CAMPAY_ENVIRONMENT  # "TEST" or "PROD"
                })
                
                # Process payment with CamPay SDK
                # In the payment processing section of complete_athlete_profile view
                try:
                    payment_response = campay_client.collect({
                        "amount": str(int(athlete.membership_fee)),
                        "currency": "XAF",
                        "from": mobile_number,
                        "description": f"Athlete membership fee for {athlete.get_full_name()}",
                        "external_reference": payment_reference
                    })
                    
                    logger.info(f"Full payment response: {payment_response}")
                    
                    # Check if we got a proper response first
                    if not payment_response:
                        logger.error("Empty payment response received")
                        messages.error(request, "Payment system error: No response received")
                        return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
                    
                    # Handle UNAUTHORIZED error specifically
                    if isinstance(payment_response, dict) and payment_response.get('status') == 'FAILED' and payment_response.get('message') == 'UNAUTHORIZED':
                        logger.error(f"CamPay authentication failed: {payment_response}")
                        messages.error(request, "Payment system error: Authentication failed with the payment provider.")
                        # Record the failed payment attempt
                        athlete.payment_status = 'failed'
                        athlete.campay_status = 'FAILED'
                        athlete.campay_response = payment_response
                        athlete.save()
                        return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
                        
                    # Continue with normal reference checking
                    if not payment_response.get('reference'):
                        logger.error(f"Missing reference in payment response: {payment_response}")
                        messages.error(request, "Payment system error: No reference received")
                        return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
                    
                    # Record payment information
                    athlete.campay_reference = payment_response.get("reference")
                    athlete.campay_transaction_id = payment_response.get("reference")
                    athlete.campay_status = payment_response.get("status")
                    athlete.campay_response = payment_response
                    athlete.save()
                    
                    logger.info(f"Payment reference saved: {athlete.campay_reference}")
                    
                    if payment_response.get('status') == 'SUCCESSFUL':
                        # Update user status for successful payment
                        athlete.payment_status = 'paid'
                        athlete.last_payment_date = timezone.now()
                        athlete.next_payment_due = timezone.now() + timezone.timedelta(days=30)
                        athlete.account_status = 'active'
                        
                        # Generate receipt
                        receipt_filename, receipt_file = generate_pdf_receipt(athlete)
                        athlete.payment_receipt = ContentFile(receipt_file.getvalue(), name=receipt_filename)
                        
                        athlete.save()
                        
                        messages.success(request, "Profile completed successfully! Your payment has been processed.")
                        return redirect('athlete_dashboard')
                    else:
                        # Payment is pending or needs further action
                        athlete.payment_status = 'pending'
                        athlete.save()
                        
                        messages.info(request, "Your profile has been saved. Please complete the payment process on your mobile device.")
                        
                        # Make sure we're using the correct reference
                        payment_reference = payment_response.get("reference")
                        logger.info(f"Redirecting to payment status with reference: {payment_reference}")
                        return redirect('payment_status', reference=payment_reference)
                
                except Exception as e:
                    logger.error(f"Payment processing error: {str(e)}", exc_info=True)
                    messages.error(request, f"Payment processing failed: {str(e)}")
                    
                    # Record failed payment
                    athlete.payment_status = 'failed'
                    athlete.campay_status = 'FAILED'
                    athlete.campay_response = {'error': str(e)}
                    athlete.save()
                    return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {'form': form})
            
            except Exception as e:
                logger.error(f"Profile completion error: {str(e)}", exc_info=True)
                messages.error(request, f"Error while completing profile: {str(e)}")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = AthleteProfileForm(instance=request.user)
        # Pre-fill mobile number if available
        if request.user.mobile_number:
            form.initial['mobile_number'] = request.user.mobile_number
    
    # Get membership fee for display
    membership_fee = request.user.membership_fee
    
    return render(request, 'Dashboards/Athlete/CompleteProfile/complete_profile.html', {
        'form': form,
        'membership_fee': membership_fee
    })

# Apply decorator to athlete_dashboard
@login_required
@profile_completion_required
def athlete_dashboard(request):
    return render(request, 'Dashboards/Athlete/AthletePanel.html')

# Add a new view to check profile completion status
@login_required
def check_profile_completion(request):
    """API endpoint to check if user profile is complete"""
    if request.user.is_authenticated:
        is_complete = request.user.is_profile_complete()
        return JsonResponse({
            'is_complete': is_complete,
            'redirect_url': reverse('complete_athlete_profile') if not is_complete else None
        })
    return JsonResponse({'error': 'Authentication required'}, status=401)

# Update the User model's is_profile_complete method to be more robust
def is_profile_complete(self):
    """Check if the user has completed their profile based on their user type"""
    if self.user_type == 'athlete':
        required_fields = [
            self.first_name, 
            self.last_name, 
            self.email,
            self.sport,
            self.level,
            self.town,
            self.quartier,
            self.profile_image,
            self.payment_status == 'paid'  # Added payment check
        ]
        return all(required_fields)
    elif self.user_type in ['psychologist', 'coach', 'nutritionist']:
        required_fields = [
            self.first_name, 
            self.last_name, 
            self.email,
            self.qualifications,
            self.years_experience,
            self.town,
            self.profile_image,
            self.certification_document,
            self.cv_document,
            self.payment_status == 'paid'  # Added payment check
        ]
        return all(required_fields)
    return True  # Admins don't need complete profiles

@login_required
def payment_status(request, reference):
    """View to check and display payment status"""
    try:
        # Get user's transaction
        user = request.user
        
        if not user.campay_reference or user.campay_reference != reference:
            messages.error(request, "Invalid payment reference.")
            return redirect('athlete_dashboard')
        
        # Check payment status with CamPay
        try:
            # Use the correct method name - most likely 'status' or 'get_status'
            status_response = campay_client.status(reference)
            # OR if the method is get_status
            # status_response = campay_client.get_status(reference)
            
            logger.info(f"Payment status response: {status_response}")
            
            # Update payment information
            user.campay_status = status_response.get("status")
            user.campay_response = status_response
            
            if status_response.get('status') == 'SUCCESSFUL':
                # Update user status for successful payment
                user.payment_status = 'paid'
                user.last_payment_date = timezone.now()
                user.next_payment_due = timezone.now() + timezone.timedelta(days=30)
                user.account_status = 'active'
                
                # Generate receipt
                receipt_filename, receipt_file = generate_pdf_receipt(user)
                user.payment_receipt = ContentFile(receipt_file.getvalue(), name=receipt_filename)
                
                user.save()
                
                messages.success(request, "Payment successful! Your profile is now complete.")
                return redirect('athlete_dashboard')
            else:
                # Payment is still pending or failed
                status = status_response.get('status', 'UNKNOWN').upper()
                if status == 'FAILED':
                    user.payment_status = 'failed'
                    messages.error(request, "Payment failed. Please try again.")
                else:
                    user.payment_status = 'pending'
                    messages.info(request, "Your payment is still processing. Please check back later.")
                
                user.save()
        
        except Exception as e:
            logger.error(f"Error checking payment status: {str(e)}")
            messages.error(request, f"Error checking payment status: {str(e)}")
            
    except Exception as e:
        logger.error(f"Payment status view error: {str(e)}")
        messages.error(request, "An error occurred while checking your payment status.")
    
    return render(request, 'Dashboards/Athlete/CompleteProfile/PaymentStatus.html', {
        'reference': reference,
        'status': user.campay_status,
        'payment_date': user.last_payment_date
    })


def generate_pdf_receipt(user):
    """Generate a PDF receipt for the user's payment"""
    try:
        # Context data for the receipt template
        context = {
            'user': user,
            'payment_date': user.last_payment_date or timezone.now(),
            'amount': user.membership_fee,
            'reference': user.campay_reference,
            'transaction_id': user.campay_transaction_id,
            'next_payment_date': user.next_payment_due,
            'generated_date': timezone.now(),
            'receipt_number': f"REC-{timezone.now().strftime('%Y%m%d')}-{user.id}"
        }
        
        # Render the receipt template
        html_string = render_to_string('Dashboards/Athlete/Receipts/MembershipReceipt.html', context)
        
        # Create a PDF file
        result = BytesIO()
        pdf = pisa.pisaDocument(BytesIO(html_string.encode("UTF-8")), result)
        
        if not pdf.err:
            # Generate a unique filename
            filename = f"membership_receipt_{user.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            return filename, result
        else:
            logger.error(f"Error generating PDF receipt: {pdf.err}")
            raise Exception("Error generating PDF receipt")
    except Exception as e:
        logger.error(f"Error in generate_pdf_receipt: {str(e)}")
        raise

@login_required
def download_receipt(request):
    """View to download the user's payment receipt"""
    user = request.user
    
    if not hasattr(user, 'payment_receipt') or not user.payment_receipt:
        messages.error(request, "No receipt available. Please complete your payment first.")
        return redirect('athlete_dashboard')
    
    try:
        # Get the file path
        file_path = user.payment_receipt.path
        
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                response = HttpResponse(f, content_type='application/pdf')
                response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
                return response
        else:
            messages.error(request, "Receipt file not found.")
            return redirect('athlete_dashboard')
    except Exception as e:
        logger.error(f"Error downloading receipt: {str(e)}")
        messages.error(request, f"Error downloading receipt: {str(e)}")
        return redirect('athlete_dashboard')




    