from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
import random

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates default users with realistic data for testing the application'

    def add_arguments(self, parser):
        parser.add_argument('--count', type=int, default=1, help='Number of users to create per type')
        parser.add_argument('--type', type=str, help='Specific user type to create (athlete, psychologist, coach, nutritionist, admin)')

    def handle(self, *args, **options):
        count = options['count']
        specific_type = options.get('type')
        
        user_types = ['athlete', 'psychologist', 'coach', 'nutritionist', 'admin']
        if specific_type:
            if specific_type not in user_types:
                self.stdout.write(self.style.ERROR(f'Invalid user type. Choose from: {", ".join(user_types)}'))
                return
            user_types = [specific_type]
            
        # Create superuser admin first
        self._create_superuser()
        
        # Create default users with realistic data
        for user_type in user_types:
            self._create_users_by_type(user_type, count)
            
        self.stdout.write(self.style.SUCCESS('User creation completed'))

    def _create_superuser(self):
        """Create a superuser admin with all privileges"""
        username = 'admin'
        email = 'admin@example.com'
        password = 'Admin123!'
        
        if User.objects.filter(username=username).exists():
            self.stdout.write(self.style.WARNING(f'Superuser {username} already exists. Skipping.'))
            return
            
        User.objects.create_superuser(
            username=username,
            email=email,
            password=password,
            first_name='Admin',
            last_name='User',
            user_type='admin',
            terms_accepted=True,
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created superuser: {username} (password: {password})'
            )
        )

    def _create_users_by_type(self, user_type, count):
        """Create users of specific type with realistic data"""
        
        # Realistic data templates
        athlete_data = [
            {
                'first_name': 'Michael', 'last_name': 'Johnson', 'sport': 'boxing', 
                'level': 'professional', 'password': 'Fighter123!'
            },
            {
                'first_name': 'Sarah', 'last_name': 'Lee', 'sport': 'judo', 
                'level': 'elite', 'password': 'Fighter123!'
            },
            {
                'first_name': 'Carlos', 'last_name': 'Rodriguez', 'sport': 'mma', 
                'level': 'professional', 'password': 'Fighter123!'
            },
            {
                'first_name': 'Aisha', 'last_name': 'Khan', 'sport': 'taekwondo', 
                'level': 'elite', 'password': 'Fighter123!'
            },
            {
                'first_name': 'James', 'last_name': 'Wilson', 'sport': 'wrestling', 
                'level': 'semi-pro', 'password': 'Fighter123!'
            }
        ]
        
        psychologist_data = [
            {
                'first_name': 'Dr. Emma', 'last_name': 'Richards', 
                'qualifications': 'Ph.D. in Sports Psychology, Licensed Clinical Psychologist',
                'years_experience': 12, 'password': 'Psych123!'
            },
            {
                'first_name': 'Dr. Robert', 'last_name': 'Chen', 
                'qualifications': 'Psy.D., Specialized in Performance Psychology',
                'years_experience': 8, 'password': 'Psych123!'
            },
            {
                'first_name': 'Dr. Maya', 'last_name': 'Patel', 
                'qualifications': 'Ph.D. in Clinical Psychology, Sports Mental Health Specialist',
                'years_experience': 15, 'password': 'Psych123!'
            }
        ]
        
        coach_data = [
            {
                'first_name': 'Thomas', 'last_name': 'Garcia', 
                'qualifications': 'Certified Mental Performance Consultant, Former Olympic Athlete',
                'years_experience': 10, 'password': 'Coach123!'
            },
            {
                'first_name': 'Jessica', 'last_name': 'Brown', 
                'qualifications': 'Sports Performance Coach, M.S. in Exercise Physiology',
                'years_experience': 7, 'password': 'Coach123!'
            },
            {
                'first_name': 'Marcus', 'last_name': 'Taylor', 
                'qualifications': 'Performance Mindset Coach, Former UFC Fighter',
                'years_experience': 11, 'password': 'Coach123!'
            }
        ]
        
        nutritionist_data = [
            {
                'first_name': 'Laura', 'last_name': 'Martinez', 
                'qualifications': 'Registered Dietitian, Sports Nutrition Specialist',
                'years_experience': 8, 'password': 'Nutri123!'
            },
            {
                'first_name': 'Daniel', 'last_name': 'Cooper', 
                'qualifications': 'M.S. in Nutrition Science, Certified Sports Nutritionist',
                'years_experience': 6, 'password': 'Nutri123!'
            },
            {
                'first_name': 'Olivia', 'last_name': 'Smith', 
                'qualifications': 'Ph.D. in Nutritional Sciences, Combat Sports Specialist',
                'years_experience': 9, 'password': 'Nutri123!'
            }
        ]
        
        admin_data = [
            {
                'first_name': 'David', 'last_name': 'Wilson', 
                'password': 'Admin123!'
            },
            {
                'first_name': 'Sophia', 'last_name': 'Anderson', 
                'password': 'Admin123!'
            }
        ]
        
        # Select appropriate data template
        data_templates = {
            'athlete': athlete_data,
            'psychologist': psychologist_data,
            'coach': coach_data,
            'nutritionist': nutritionist_data,
            'admin': admin_data
        }
        
        templates = data_templates[user_type]
        
        # Create users
        for i in range(count):
            # Get template data, cycling through available templates
            template_index = i % len(templates)
            template = templates[template_index]
            
            # Create a unique suffix for email if needed
            suffix = f"{i+1}" if i >= len(templates) else ""
            
            # Base user data
            first_name = template['first_name']
            last_name = template['last_name']
            username = f"{first_name.lower().replace('dr. ', '')}{last_name.lower()}{suffix}"
            email = f"{username}@example.com"
            password = template['password']
            
            # Skip if user already exists
            if User.objects.filter(username=username).exists():
                self.stdout.write(self.style.WARNING(f'User {username} already exists. Skipping.'))
                continue
            
            # Prepare user data
            user_data = {
                'username': username,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'user_type': user_type,
                'terms_accepted': True,
            }
            
            # Add type-specific fields
            if user_type == 'athlete':
                user_data.update({
                    'sport': template['sport'],
                    'level': template['level'],
                })
            elif user_type in ['psychologist', 'coach', 'nutritionist']:
                user_data.update({
                    'qualifications': template['qualifications'],
                    'years_experience': template['years_experience'],
                })
            
            # Create user
            user = User.objects.create(**user_data)
            user.set_password(password)
            
            # Make admin users staff users as well
            if user_type == 'admin':
                user.is_staff = True
                
            user.save()
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully created {user_type}: {username} (password: {password})'
                )
            )