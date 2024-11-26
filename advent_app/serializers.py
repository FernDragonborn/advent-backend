from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.encoding import DjangoUnicodeDecodeError, smart_str
from django.utils.http import urlsafe_base64_decode

from advent_app.models import User, Task, TaskResponse, EmailVerification
from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password

from advent_backend import settings


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'gender', 'region', 'grade')
        read_only_fields = ['email']


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task

class TaskResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = TaskResponse



class RegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        """
        Create user and generate verification code
        """
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            phone_number=validated_data.get('phone_number', ''),
            is_active=False  # Set user as inactive initially
        )

        # Create email verification record
        verification = EmailVerification.objects.create(user=user)
        code = verification.generate_verification_code()

        # Send verification email
        send_mail(
            'Verify Your Email',
            f'Your verification code is: {code}',
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            html_message=self._get_email_template(code)
        )

        return user

    def _get_email_template(self, code):
        """
        HTML email template for verification
        """
        return f'''
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Email Verification</h2>
            <p>Your verification code is:</p>
            <h3 style="background-color: #f4f4f4;
                       padding: 10px;
                       text-align: center;
                       letter-spacing: 5px;
                       font-size: 24px;">{code}</h3>
            <p>This code will expire in 1 hour.</p>
        </div>
        '''

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])


class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Токен скидання пароля невірний.', code='authorization')

            user.set_password(password)
            user.save()

            return user
        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError('Токен скидання пароля невірний.', code='authorization')
        except User.DoesNotExist:
            raise serializers.ValidationError('Користувач не знайдений.', code='authorization')