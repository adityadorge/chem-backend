#app1/custom_auth_backend.py
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.authtoken.models import Token

User = get_user_model()

""" This custom authentication backend allows the application 
        to authenticate users based on a token stored in a cookie, 
        which can be useful for scenarios where you want to maintain 
        user sessions across different parts of your application or API.
        It extends Django Rest Framework's BaseAuthentication
"""
class CookieTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_token = request.COOKIES.get('auth_token')
        if not auth_token:
            return None
        try:
            token = Token.objects.get(key=auth_token)
        except Token.DoesNotExist:
            raise AuthenticationFailed('Invalid token')

        if not token.user.is_active:
            raise AuthenticationFailed('User inactive or deleted')

        return (token.user, token)