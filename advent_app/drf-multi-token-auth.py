from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework import exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from oauth2_provider.models import AccessToken as OAuth2AccessToken
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class MultiTokenAuthentication(BaseAuthentication):
    """
    Custom authentication class to support multiple token types
    Priority order: 
    1. JWT Token
    2. OAuth2 Token
    3. Other custom token types can be added
    """
    def authenticate(self, request):
        """
        Attempt authentication with different token types
        """
        # Extract authorization header
        auth = get_authorization_header(request).decode('utf-8').split()
        
        # No authorization header
        if not auth:
            return None
        
        # Ensure proper authorization header format
        if len(auth) != 2:
            return None
        
        token_type, token = auth
        token_type = token_type.lower()

        # JWT Token Authentication
        if token_type == b'jwt'.lower():
            try:
                jwt_auth = JWTAuthentication()
                validated_token = jwt_auth.get_validated_token(token)
                user = jwt_auth.get_user(validated_token)
                return (user, validated_token)
            except Exception:
                raise exceptions.AuthenticationFailed('Invalid JWT token')
        
        # OAuth2 Token Authentication
        elif token_type == b'bearer'.lower():
            try:
                # First try OAuth2 authentication
                oauth_token = OAuth2AccessToken.objects.get(
                    token=token, 
                    expires__gt=timezone.now()
                )
                return (oauth_token.user, token)
            except OAuth2AccessToken.DoesNotExist:
                # If OAuth2 fails, try JWT authentication
                try:
                    jwt_auth = JWTAuthentication()
                    validated_token = jwt_auth.get_validated_token(token)
                    user = jwt_auth.get_user(validated_token)
                    return (user, validated_token)
                except Exception:
                    raise exceptions.AuthenticationFailed('Invalid token')
        
        # Custom token types can be added here
        
        # If no matching token type is found
        return None

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthorized` response.
        """
        return 'Bearer realm="api"'

# Configuration for settings.py
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'path.to.MultiTokenAuthentication',
        # Fallback to default authentication methods
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'oauth2_provider.authentication.OAuth2Authentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    # Other DRF settings...
}

# Optional: Custom token validation view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

class TokenValidationView(APIView):
    """
    View to validate different types of tokens
    """
    authentication_classes = [MultiTokenAuthentication]
    permission_classes = []

    def post(self, request):
        """
        Validate token and return user information
        """
        try:
            # If authentication succeeds, user is authenticated
            return Response({
                'valid': True,
                'user_id': request.user.id,
                'username': request.user.username,
                'email': request.user.email
            }, status=status.HTTP_200_OK)
        except exceptions.AuthenticationFailed:
            return Response({
                'valid': False,
                'error': 'Invalid or expired token'
            }, status=status.HTTP_401_UNAUTHORIZED)