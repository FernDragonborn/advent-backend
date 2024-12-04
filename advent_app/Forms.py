from django.contrib.auth import authenticate
from django import forms
from captcha.fields import ReCaptchaField

class EmailAuthenticationForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = ReCaptchaField()

    def clean(self):
        email = self.cleaned_data.get('email')
        password = self.cleaned_data.get('password')

        user = authenticate(email=email, password=password)
        if not user:
            raise forms.ValidationError("Неправильний email або пароль")
        self.user = user
        return self.cleaned_data

    def get_user(self):
        return self.user
