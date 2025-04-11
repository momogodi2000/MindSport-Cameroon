from django import forms
from .models import ContactMessage, NewsletterSubscriber
from django import forms
from django.contrib.auth.forms import UserCreationForm
from .models import User
from django import forms
from django.core.validators import MinValueValidator, MaxValueValidator
from .models import User
from django import forms
from .models import User

class ContactForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'subject', 'message']
        
class NewsletterForm(forms.ModelForm):
    class Meta:
        model = NewsletterSubscriber
        fields = ['email']

class UserRegistrationForm(UserCreationForm):
    first_name = forms.CharField(max_length=30, required=True)
    last_name = forms.CharField(max_length=30, required=True)
    email = forms.EmailField(required=True)
    user_type = forms.ChoiceField(choices=User.USER_TYPE_CHOICES, required=True)
    sport = forms.ChoiceField(choices=User.SPORT_CHOICES, required=False)
    level = forms.ChoiceField(choices=User.LEVEL_CHOICES, required=False)
    qualifications = forms.CharField(max_length=255, required=False)
    years_experience = forms.IntegerField(
        min_value=0, 
        max_value=50, 
        required=False,
        widget=forms.NumberInput(attrs={'type': 'number'})
    )
    terms_accepted = forms.BooleanField(required=True)
    
    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'user_type',
            'sport', 'level', 'qualifications', 'years_experience',
            'password1', 'password2', 'terms_accepted'
        ]
    
    def clean(self):
        cleaned_data = super().clean()
        user_type = cleaned_data.get('user_type')
        
        if user_type == 'athlete':
            if not cleaned_data.get('sport'):
                self.add_error('sport', 'This field is required for athletes')
            if not cleaned_data.get('level'):
                self.add_error('level', 'This field is required for athletes')
        
        if user_type in ['psychologist', 'coach', 'nutritionist']:
            if not cleaned_data.get('qualifications'):
                self.add_error('qualifications', 'This field is required for professionals')
            if not cleaned_data.get('years_experience'):
                self.add_error('years_experience', 'This field is required for professionals')
        
        return cleaned_data
    
class AthleteProfileForm(forms.ModelForm):
    mobile_number = forms.CharField(max_length=20, required=True, 
                                    widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your mobile number'}))
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'profile_image', 'sport', 'level', 'town', 'quartier']
        widgets = {
            'first_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your first name'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your last name'}),
            'sport': forms.Select(attrs={'class': 'form-control'}),
            'level': forms.Select(attrs={'class': 'form-control'}),
            'town': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your town'}),
            'quartier': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter your quartier'}),
            'profile_image': forms.FileInput(attrs={'class': 'form-input'})
        }

    def __init__(self, *args, **kwargs):
        super(AthleteProfileForm, self).__init__(*args, **kwargs)
        # Set all fields as required
        for field in self.fields:
            self.fields[field].required = True

    def clean_profile_image(self):
        image = self.cleaned_data.get('profile_image')
        if not image:
            raise forms.ValidationError("Profile image is required.")
        return image

class SocialSignupForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['user_type', 'sport', 'level', 'qualifications', 'years_experience']
        widgets = {
            'user_type': forms.Select(attrs={'class': 'form-input'}),
            'sport': forms.Select(attrs={'class': 'form-input'}),
            'level': forms.Select(attrs={'class': 'form-input'}),
            'qualifications': forms.TextInput(attrs={'class': 'form-input'}),
            'years_experience': forms.NumberInput(attrs={'class': 'form-input'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['terms_accepted'] = forms.BooleanField(
            required=True,
            widget=forms.CheckboxInput(attrs={'class': 'h-4 w-4 text-blue-600 border-gray-300 rounded'}),
            label='I agree to the Terms of Service and Privacy Policy'
        )
        
        # Make fields required based on user type
        self.fields['sport'].required = False
        self.fields['level'].required = False
        self.fields['qualifications'].required = False
        self.fields['years_experience'].required = False
    
    def clean(self):
        cleaned_data = super().clean()
        user_type = cleaned_data.get('user_type')
        
        if user_type == 'athlete':
            if not cleaned_data.get('sport'):
                self.add_error('sport', 'This field is required for athletes')
            if not cleaned_data.get('level'):
                self.add_error('level', 'This field is required for athletes')
        
        if user_type in ['psychologist', 'coach', 'nutritionist']:
            if not cleaned_data.get('qualifications'):
                self.add_error('qualifications', 'This field is required for professionals')
            if not cleaned_data.get('years_experience'):
                self.add_error('years_experience', 'This field is required for professionals')
        
        return cleaned_data



