from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from allauth.exceptions import ImmediateHttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from .models import User

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        user = sociallogin.user
        if user.id:
            return
        
        try:
            # Check if social account already exists
            existing_user = User.objects.get(email=user.email)
            sociallogin.connect(request, existing_user)
            raise ImmediateHttpResponse(redirect(reverse('redirect_after_social_login')))
        except User.DoesNotExist:
            pass

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        user.social_provider = sociallogin.account.provider
        user.social_uid = sociallogin.account.uid
        return user