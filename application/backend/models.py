from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _
from django.db import migrations, models
import django.db.models.deletion
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone



class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Message from {self.name} - {self.subject}"

class NewsletterSubscriber(models.Model):
    email = models.EmailField(unique=True)
    subscribed_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    def __str__(self):
        return self.email
    
class User(AbstractUser):
    USER_TYPE_CHOICES = (
        ('athlete', 'Athlete'),
        ('psychologist', 'Psychologist'),
        ('coach', 'Mental Coach'),
        ('nutritionist', 'Nutritionist'),
        ('admin', 'Administrator'),
    )
    
    SPORT_CHOICES = (
        ('boxing', 'Boxing'),
        ('wrestling', 'Wrestling'),
        ('judo', 'Judo'),
        ('karate', 'Karate'),
        ('taekwondo', 'Taekwondo'),
        ('mma', 'Mixed Martial Arts'),
        ('other', 'Other'),
    )
    
    LEVEL_CHOICES = (
        ('amateur', 'Amateur'),
        ('semi-pro', 'Semi-Professional'),
        ('professional', 'Professional'),
        ('elite', 'Elite'),
    )
    
    ACCOUNT_STATUS_CHOICES = (
        ('pending', 'Pending Verification'),
        ('active', 'Active'),
        ('blocked', 'Blocked'),
        ('suspended', 'Temporarily Suspended'),
    )
    
    # Basic profile fields
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='athlete')
    sport = models.CharField(max_length=20, choices=SPORT_CHOICES, blank=True, null=True)
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, blank=True, null=True)
    qualifications = models.CharField(max_length=255, blank=True, null=True)
    years_experience = models.PositiveIntegerField(
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(50)]
    )
    
    # Profile fields
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    town = models.CharField(max_length=100, blank=True, null=True)
    quartier = models.CharField(max_length=100, blank=True, null=True)
    account_status = models.CharField(
        max_length=20, 
        choices=ACCOUNT_STATUS_CHOICES, 
        default='pending'
    )
    
    # Professional verification fields
    is_verified_professional = models.BooleanField(default=False)
    license_number = models.CharField(max_length=100, blank=True, null=True)
    certification_document = models.FileField(
        upload_to='certification_documents/', 
        blank=True, 
        null=True,
        help_text='Upload your professional certification or license'
    )
    cv_document = models.FileField(
        upload_to='cv_documents/', 
        blank=True, 
        null=True,
        help_text='Upload your professional CV or resume'
    )
    additional_documents = models.FileField(
        upload_to='additional_documents/', 
        blank=True, 
        null=True,
        help_text='Upload any additional supporting documents'
    )
    verification_notes = models.TextField(blank=True, null=True)
    
    # Payment related fields
    membership_fee = models.DecimalField(
        max_digits=8, 
        decimal_places=2, 
        default=0.00,
        help_text='Monthly membership fee based on user type'
    )
    mobile_number = models.CharField(max_length=20, blank=True, null=True)
    last_payment_date = models.DateTimeField(blank=True, null=True)
    next_payment_due = models.DateTimeField(blank=True, null=True)
    payment_status = models.CharField(
        max_length=20,
        choices=(
            ('pending', 'Pending'),
            ('paid', 'Paid'),
            ('failed', 'Failed'),
            ('expired', 'Expired'),
        ),
        default='pending'
    )
    
    # Campay specific fields
    campay_reference = models.CharField(max_length=255, blank=True, null=True)
    campay_transaction_id = models.CharField(max_length=255, blank=True, null=True)
    campay_status = models.CharField(max_length=50, blank=True, null=True)
    campay_response = models.JSONField(blank=True, null=True)
    
    # Receipt field
    payment_receipt = models.FileField(
        upload_to='receipts/',
        blank=True,
        null=True,
        help_text='PDF receipt for membership payment'
    )
    # Other fields
    terms_accepted = models.BooleanField(default=False)
    social_provider = models.CharField(max_length=20, blank=True, null=True)
    social_uid = models.CharField(max_length=200, blank=True, null=True)
    date_verified = models.DateTimeField(blank=True, null=True)
    
    def save(self, *args, **kwargs):
        # Set default membership fees based on user type
        if not self.pk or self.membership_fee == 0.00:  # Only set on creation or if not manually set
            if self.user_type == 'athlete':
                self.membership_fee = 05.00  # CFA
            elif self.user_type == 'psychologist':
                self.membership_fee = 07.00  # CFA
            elif self.user_type == 'coach':
                self.membership_fee = 08.00  # CFA
            elif self.user_type == 'nutritionist':
                self.membership_fee = 10.00  # CFA
            elif self.user_type == 'admin':
                self.membership_fee = 0.00
        super().save(*args, **kwargs)
    
    def is_profile_complete(self):
        """Check if the user has completed their profile based on their user type"""
        if self.user_type == 'athlete':
            return all([
                self.first_name, 
                self.last_name, 
                self.email,
                self.sport,
                self.level,
                self.town,
                self.profile_image,
                self.payment_status == 'paid'  # Added payment check
            ])
        elif self.user_type in ['psychologist', 'coach', 'nutritionist']:
            return all([
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
            ])
        return True  # Admins don't need complete profiles
    
    def record_payment(self, reference, transaction_id=None, status=None, response_data=None):
        """Record a payment attempt with Campay"""
        self.campay_reference = reference
        if transaction_id:
            self.campay_transaction_id = transaction_id
        if status:
            self.campay_status = status
            
            # Update payment status based on Campay status
            if status.lower() in ['success', 'successful', 'completed']:
                self.payment_status = 'paid'
                self.last_payment_date = timezone.now()
                self.next_payment_due = timezone.now() + timezone.timedelta(days=30)
            elif status.lower() in ['failed', 'rejected', 'cancelled']:
                self.payment_status = 'failed'
        
        if response_data:
            self.campay_response = response_data
            
        self.save()
    
    def is_subscription_active(self):
        """Check if user's subscription is active"""
        if self.payment_status != 'paid':
            return False
        
        if not self.next_payment_due:
            return False
            
        return timezone.now() < self.next_payment_due
    
    def __str__(self):
        return f"{self.get_full_name()} ({self.get_user_type_display()})"

class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0XXX_previous_migration'),  # Replace with your latest migration
    ]

    operations = [
        migrations.CreateModel(
            name='PasswordResetToken',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                ('verification_code', models.CharField(max_length=6)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField()),
                ('is_used', models.BooleanField(default=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='authentication.User')),
            ],
        ),
    ]



