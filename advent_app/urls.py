# advent_app/urls.py

from django.urls import path
from .views import (
    RegistrationView,
    UserDetailView,
    ChangePasswordView,
    RequestPasswordResetEmail,
    PasswordTokenCheckAPI,
    SetNewPasswordAPIView,
    LoginView,
    LogoutView,
    EmailVerificationView,
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)


urlpatterns = [
    path('register/', RegistrationView.as_view(), name='auth_register'),
    path('verify-email/', EmailVerificationView.as_view(), name='auth_verify_email'),
    path('user/', UserDetailView.as_view(), name='user_detail'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('token/', LoginView.as_view(), name='token_obtain_pair'),
    path('revoke-token/', LogoutView.as_view(), name='token_revoke'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 


    # Endpoints для скидання пароля
    path('password-reset/', RequestPasswordResetEmail.as_view(), name='password_reset'),
    path('password-reset-confirm/', PasswordTokenCheckAPI.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password_reset_complete'),
]