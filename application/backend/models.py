from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import gettext_lazy as _
from django.db import migrations, models
import django.db.models.deletion
import uuid


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
    
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='athlete')
    sport = models.CharField(max_length=20, choices=SPORT_CHOICES, blank=True, null=True)
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, blank=True, null=True)
    qualifications = models.CharField(max_length=255, blank=True, null=True)
    years_experience = models.PositiveIntegerField(
        blank=True, 
        null=True,
        validators=[MinValueValidator(0), MaxValueValidator(50)]
    )
    terms_accepted = models.BooleanField(default=False)
    social_provider = models.CharField(max_length=20, blank=True, null=True)
    social_uid = models.CharField(max_length=200, blank=True, null=True)
    

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



