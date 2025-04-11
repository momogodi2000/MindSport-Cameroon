from django.contrib.auth import logout
from django.utils import timezone
from django.conf import settings
from django.shortcuts import redirect

class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip for non-authenticated users
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Check session last activity
        last_activity = request.session.get('last_activity')
        now = timezone.now().timestamp()

        if last_activity and now - last_activity > settings.SESSION_COOKIE_AGE:
            logout(request)
            return redirect('login')  # Redirect to login page after logout

        # Update last activity time
        request.session['last_activity'] = now

        return self.get_response(request)
