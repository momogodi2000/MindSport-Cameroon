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
    status = request.GET.get('status')
    search_query = request.GET.get('search', '')
    
    if user_type:
        users = users.filter(user_type=user_type)
    
    if sport:
        users = users.filter(sport=sport)
    
    if level:
        users = users.filter(level=level)
    
    if status:
        is_active = status == 'active'
        users = users.filter(is_active=is_active)
    
    if search_query:
        users = users.filter(
            Q(first_name__icontains=search_query) | 
            Q(last_name__icontains=search_query) | 
            Q(email__icontains=search_query)
        )
    
    # Pagination
    from django.core.paginator import Paginator
    paginator = Paginator(users, 10)  # Show 10 users per page
    page_number = request.GET.get('page', 1)
    users_page = paginator.get_page(page_number)
    
    # User growth data for chart
    user_growth = get_user_growth_data()
    
    context = {
        'users': users_page,
        'statistics': statistics,
        'user_growth_months': json.dumps(user_growth['months']),
        'user_growth_data': json.dumps(user_growth['data'])
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
        'active_users': User.objects.filter(is_active=True).count(),
        'inactive_users': User.objects.filter(is_active=False).count(),
        
        # Sport counts
        'boxing_count': User.objects.filter(sport='boxing').count(),
        'wrestling_count': User.objects.filter(sport='wrestling').count(),
        'judo_count': User.objects.filter(sport='judo').count(),
        'karate_count': User.objects.filter(sport='karate').count(),
        'taekwondo_count': User.objects.filter(sport='taekwondo').count(),
        'mma_count': User.objects.filter(sport='mma').count(),
        'other_sport_count': User.objects.filter(sport='other').count(),
        
        # New users in last 30 days
        'new_users_30_days': User.objects.filter(date_joined__gte=datetime.now() - timedelta(days=30)).count(),
    }
    
    return statistics

def get_user_growth_data():
    """Helper function to get user growth data for charts"""
    # Last 6 months data
    months = []
    data = []
    
    for i in range(5, -1, -1):
        date = datetime.now() - timedelta(days=30 * i)
        month_start = date.replace(day=1)
        
        if i > 0:
            next_month = datetime.now() - timedelta(days=30 * (i-1))
            month_end = next_month.replace(day=1)
        else:
            month_end = datetime.now()
        
        count = User.objects.filter(date_joined__gte=month_start, date_joined__lt=month_end).count()
        months.append(date.strftime("%b %Y"))
        data.append(count)
    
    return {'months': months, 'data': data}

@login_required
@user_passes_test(is_admin)
def admin_get_users(request):
    """API endpoint to get all users"""
    # Reuse the admin_crud view for this to maintain consistency
    return admin_crud(request)

@login_required
@user_passes_test(is_admin)
def admin_get_user(request, user_id):
    """View a single user's details"""
    user = get_object_or_404(User, id=user_id)
    return render(request, 'Dashboards/Admin/User Management/admin_user_detail.html', {'user': user})

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
            
            # Create user
            new_user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                user_type=user_type,
                sport=request.POST.get('sport'),
                level=request.POST.get('level'),
                qualifications=request.POST.get('qualifications'),
                years_experience=request.POST.get('years_experience', 0),
                is_active=request.POST.get('is_active') == 'on',
                terms_accepted=True
            )
            
            messages.success(request, f'User {first_name} {last_name} created successfully!')
            return redirect('admin_get_users')
            
        except Exception as e:
            messages.error(request, f'Error creating user: {str(e)}')
            return redirect('admin_create_user')
    
    # GET request - show create form
    return render(request, 'Dashboards/Admin/User Management/admin_create_user.html')

@login_required
@user_passes_test(is_admin)
def admin_update_user(request, user_id):
    """Update an existing user"""
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        try:
            # Process form data
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            
            # Check if email changed and is unique
            new_email = request.POST.get('email')
            if new_email != user.email and User.objects.filter(email=new_email).exists():
                messages.error(request, 'Email already in use by another account')
                return redirect('admin_update_user', user_id=user_id)
            
            user.email = new_email
            user.username = new_email  # Keep username and email in sync
            
            # Update other fields
            user.user_type = request.POST.get('user_type', user.user_type)
            user.sport = request.POST.get('sport', user.sport)
            user.level = request.POST.get('level', user.level)
            user.qualifications = request.POST.get('qualifications', user.qualifications)
            user.years_experience = request.POST.get('years_experience', user.years_experience)
            user.is_active = request.POST.get('is_active') == 'on'
            
            # Update password if provided
            password = request.POST.get('password')
            if password:
                user.set_password(password)
            
            user.save()
            messages.success(request, f'User {user.get_full_name()} updated successfully!')
            return redirect('admin_get_users')
            
        except Exception as e:
            messages.error(request, f'Error updating user: {str(e)}')
            return redirect('admin_update_user', user_id=user_id)
    
    # GET request - show update form
    return render(request, 'Dashboards/Admin/User Management/admin_update_user.html', {'user': user})

@login_required
@user_passes_test(is_admin)
@csrf_exempt
def admin_delete_user(request, user_id):
    """Delete a user"""
    if request.method in ['DELETE', 'POST']:
        try:
            user = get_object_or_404(User, id=user_id)
            
            # Prevent deleting yourself
            if user.id == request.user.id:
                messages.error(request, 'You cannot delete your own account')
                return redirect('admin_get_users')
            
            user_name = f"{user.first_name} {user.last_name}"
            user.delete()
            messages.success(request, f'User {user_name} deleted successfully!')
            
        except Exception as e:
            messages.error(request, f'Error deleting user: {str(e)}')
    
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
    
    user_growth = get_user_growth_data()
    
    context = {
        'statistics': statistics,
        'monthly_signups': list(monthly_signups),
        'athletes_by_level': list(athletes_by_level),
        'user_growth_months': json.dumps(user_growth['months']),
        'user_growth_data': json.dumps(user_growth['data'])
    }
    
    return render(request, 'Dashboards/Admin/User Management/admin_statistics.html', context)

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

# Fix the complete_athlete_profile view

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
                
                # Process payment with CamPay SDK
                try:
                    logger.info(f"Initiating payment for user {athlete.id} with amount {athlete.membership_fee}")
                    
                    payment_response = campay_client.collect({
                        "amount": str(athlete.membership_fee),
                        "currency": "XAF",
                        "from": mobile_number,
                        "description": f"Athlete membership fee for {athlete.get_full_name()}",
                        "external_reference": payment_reference
                    })
                    
                    logger.info(f"Payment response: {payment_response}")
                    
                    # Record payment information
                    athlete.campay_reference = payment_response.get("reference")
                    athlete.campay_transaction_id = payment_response.get("reference")
                    athlete.campay_status = payment_response.get("status")
                    athlete.campay_response = payment_response
                    
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
                        return redirect('payment_status', reference=payment_response.get("reference"))
                
                except Exception as e:
                    logger.error(f"Payment processing error: {str(e)}")
                    messages.error(request, f"Payment processing failed: {str(e)}")
                    
                    # Record failed payment
                    athlete.payment_status = 'failed'
                    athlete.campay_status = 'FAILED'
                    athlete.campay_response = {'error': str(e)}
                    athlete.save()
            
            except Exception as e:
                logger.error(f"Profile completion error: {str(e)}")
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
    """View to check payment status"""
    try:
        # Get the latest payment status from CamPay
        payment_info = campay_client.check_status(reference)
        
        user = request.user
        
        # Update user's payment information
        if payment_info.get('status') == 'SUCCESSFUL':
            user.payment_status = 'paid'
            user.last_payment_date = timezone.now()
            user.next_payment_due = timezone.now() + timezone.timedelta(days=30)
            user.account_status = 'active'
            user.campay_status = payment_info.get('status')
            
            # Generate receipt if not already generated
            if not hasattr(user, 'payment_receipt') or not user.payment_receipt:
                receipt_filename, receipt_file = generate_pdf_receipt(user)
                user.payment_receipt = ContentFile(receipt_file.getvalue(), name=receipt_filename)
            
            user.save()
            
            messages.success(request, "Payment successful! Your membership is now active.")
            return redirect('athlete_dashboard')
        else:
            # Payment is still pending or failed
            return render(request, 'Dashboards/Athlete/Receipts/PaymentStatus.html', {
                'payment_info': payment_info,
                'reference': reference
            })
            
    except Exception as e:
        logger.error(f"Error checking payment status: {str(e)}")
        messages.error(request, f"Error checking payment status: {str(e)}")
        return redirect('athlete_dashboard')

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




    