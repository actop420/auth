import threading
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth.models import AnonymousUser

_request_local = threading.local()

class CurrentUserMiddleware:
    """Middleware to store the current JWT-authenticated user in a thread-local variable."""
    def __init__(self, get_response):
        self.get_response = get_response
        self.jwt_authenticator = JWTAuthentication()

    def __call__(self, request):
        # Default to anonymous user
        _request_local.user = AnonymousUser()

        # Try to authenticate the user via JWT token
        if "Authorization" in request.headers:
            auth_result = self.jwt_authenticator.authenticate(request)
            if auth_result is not None:
                user, _ = auth_result
                _request_local.user = user

        response = self.get_response(request)
        return response

def get_current_authenticated_user():
    """Retrieve the current authenticated user from thread-local storage."""
    return getattr(_request_local, "user", AnonymousUser())
