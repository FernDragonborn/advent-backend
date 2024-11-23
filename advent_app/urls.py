# advent_app/urls.py

from django.urls import path
from .views import (
    RegisterView,
    UserDetailView,
    ChangePasswordView,
    RequestPasswordResetEmail,
    PasswordTokenCheckAPI,
    SetNewPasswordAPIView,
)
from oauth2_provider.views import TokenView, RevokeTokenView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('user/', UserDetailView.as_view(), name='user_detail'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('token/', TokenView.as_view(), name='token_obtain_pair'),
    path('revoke-token/', RevokeTokenView.as_view(), name='token_revoke'),

    # Endpoints для скидання пароля
    path('password-reset/', RequestPasswordResetEmail.as_view(), name='password_reset'),
    path('password-reset-confirm/', PasswordTokenCheckAPI.as_view(), name='password_reset_confirm'),
    path('password-reset-complete/', SetNewPasswordAPIView.as_view(), name='password_reset_complete'),
]
