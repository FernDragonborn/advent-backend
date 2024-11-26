from audioop import reverse
from email.message import EmailMessage

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth import get_user_model, authenticate, login
from django.contrib.auth.models import update_last_login

from drf_spectacular.openapi import AutoSchema
from oauth2_provider.contrib.rest_framework.permissions import TokenHasReadWriteScope
from oauth2_provider.views import RevokeTokenView

from advent_app.serializers import (UserSerializer, TaskSerializer, TaskResponseSerializer, RegistrationSerializer,
                                    ChangePasswordSerializer, SetNewPasswordSerializer,
                                    ResetPasswordEmailRequestSerializer)
from advent_app.models import User, Task, TaskResponse, EmailVerification
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated

from advent_backend import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken


class TaskListView(generics.ListAPIView):
    serialzer_class = TaskSerializer
    permission_classes = (IsAuthenticated,)
    schema = AutoSchema()
    
    def get_queryset(self):
        group = self.request.user.group
        return Task.objects.filter(group=group)
    
class TaskResponseListCreateView(generics.ListCreateAPIView):
    serializer_class = TaskResponseSerializer
    permission_classes = (IsAuthenticated,)
    schema = AutoSchema()
    
    def get_queryset(self):
        return TaskResponse.objects.filter(user=self.request.user)


User = get_user_model()

class RegistrationView(APIView):
    """
    View for user registration
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle user registration
        """
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({
                'message': 'Registration successful. Check your email for verification code.'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserDetailView(generics.RetrieveUpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated, """TokenHasReadWriteScope""")
    serializer_class = UserSerializer
    schema = AutoSchema()
    
    def get_object(self):
        return self.request.user


class ChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    permission_classes = (IsAuthenticated,)
    serializer_class = ChangePasswordSerializer
    schema = AutoSchema()
    
    def get_object(self, queryset=None):
        return self.request.user

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Перевірка старого пароля
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Неправильний пароль."]}, status=status.HTTP_400_BAD_REQUEST)

            # Встановлення нового пароля
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            update_last_login(None, self.object)
            return Response({"detail": "Пароль успішно змінено."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = ResetPasswordEmailRequestSerializer
    schema = AutoSchema()
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            reset_url = reverse('password_reset_confirm')

            absurl = f"{request.scheme}://{request.get_host()}{reset_url}?uidb64={uidb64}&token={token}"
            email_body = f"Привіт,\n\nВи отримали цей лист, тому що запитали скидання пароля для вашого облікового запису.\nПерейдіть за посиланням, щоб скинути пароль:\n{absurl}\n\nЯкщо ви не запитували скидання пароля, ігноруйте цей лист.\n\nДякуємо!"
            email = EmailMessage(
                'Скидання пароля',
                email_body,
                settings.DEFAULT_FROM_EMAIL,
                [email],
            )
            email.send(fail_silently=False)

        return Response({"detail": "Якщо електронна пошта існує у системі, ви отримаєте лист для скидання пароля."}, status=status.HTTP_200_OK)

class PasswordTokenCheckAPI(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    schema = AutoSchema()
    
    def get(self, request):
        token = request.GET.get('token')
        uidb64 = request.GET.get('uidb64')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({"error": "Токен скидання пароля невірний."}, status=status.HTTP_401_UNAUTHORIZED)

            return Response({"success": True, "message": "Токен дійсний."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "Токен скидання пароля невірний."}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer
    schema = AutoSchema()
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"detail": "Пароль успішно змінено."}, status=status.HTTP_200_OK)

from oauth2_provider.views import TokenView
from drf_spectacular.utils import extend_schema

@extend_schema(
    tags=["Authentication"],
    operation_id="token_obtain",
    description="Отримання токену через OAuth2",
    request={
        "application/x-www-form-urlencoded": {
            "type": "object",
            "properties": {
                "grant_type": {"type": "string", "example": "password"},
                "client_id": {"type": "string", "example": "your-client-id"},
                "client_secret": {"type": "string", "example": "your-client-secret"},
                "username": {"type": "string", "example": "user@example.com"},
                "password": {"type": "string", "example": "your-password"},
            },
            "required": ["grant_type", "client_id", "client_secret", "username", "password"],
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "access_token": {"type": "string"},
                "refresh_token": {"type": "string"},
                "expires_in": {"type": "integer"},
                "token_type": {"type": "string", "example": "Bearer"},
            },
        },
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)

class LoginView(APIView):
    """
    API View for user login using Django REST Framework
    Supports token-based authentication with JWT
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Handle user login attempt
        :param request: HTTP request containing login credentials
        :return: Response with authentication token or error message
        """
        username = request.data.get('email')
        password = request.data.get('password')

        # Validate input
        if not username or not password:
            return Response({
                'error': 'Please provide both email and password'
            }, status=status.HTTP_400_BAD_REQUEST)

        user_and_active = User.objects.filter(username=username).first()
        if not user_and_active or not user_and_active.is_active:
            return Response({"error": "User is not activated or not registered"})

        # Authenticate user
        user = authenticate(username=username, password=password)

        if user:
            # If authentication succeeds
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_id': user.id,
                'username': user.username
            }, status=status.HTTP_200_OK)

        # If authentication fails
        return Response({
            'error': 'Invalid Credentials'
        }, status=status.HTTP_401_UNAUTHORIZED)




class LogoutView(APIView):
    """
    API View for user logout using Django REST Framework
    Supports token blacklisting with JWT
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handle user logout
        Blacklists the refresh token to invalidate it
        :param request: HTTP request from authenticated user
        :return: Response indicating successful logout
        """
        try:
            # Get the refresh token from the request
            refresh_token = request.data.get('refresh_token')

            if not refresh_token:
                return Response({
                    'error': 'Refresh token is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({
                'message': 'Successfully logged out'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'error': 'Invalid token or logout failed'
            }, status=status.HTTP_400_BAD_REQUEST)

@extend_schema(
    tags=["Authentication"],
    operation_id="token_revoke",
    description="Відкликання токена (доступу або оновлення) через OAuth2.",
    request={
        "application/x-www-form-urlencoded": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "example": "your-access-or-refresh-token"},
                "client_id": {"type": "string", "example": "your-client-id"},
                "client_secret": {"type": "string", "example": "your-client-secret"},
            },
            "required": ["token", "client_id", "client_secret"],
        }
    },
    responses={
        200: {"type": "object", "properties": {"success": {"type": "boolean", "example": True}}},
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)
class CustomRevokeTokenView(RevokeTokenView):
    """Custom wrapper for RevokeTokenView to include schema."""
    pass

class EmailVerificationView(APIView):
    """
    View for email verification
    """
    permission_classes = [AllowAny]

    def post(self, request):
        """
        Verify email using provided code
        """
        email = request.data.get('email')
        code = request.data.get('verification_code')

        # Validate input
        if not email or not code:
            return Response({
                'error': 'Email and verification code are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Find user and verification record
            user = User.objects.get(email=email, is_active=False)
            verification = EmailVerification.objects.get(
                user=user,
                verification_code=code
            )

            # Activate user
            user.is_active = True
            user.save()

            # Delete verification record
            verification.delete()

            return Response({
                'message': 'Email successfully verified. You can now log in.'
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({
                'error': 'Invalid email or user already activated'
            }, status=status.HTTP_404_NOT_FOUND)

        except EmailVerification.DoesNotExist:
            return Response({
                'error': 'Invalid or expired verification code'
            }, status=status.HTTP_400_BAD_REQUEST)
