#!/bin/bash

# Зупинити виконання скрипту при помилці
set -e

# Виконати міграції
echo "Виконання міграцій..."
python manage.py migrate

# Створення суперкористувача
echo "Перевірка наявності суперкористувача..."
python manage.py shell <<EOF
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'adminpassword')
EOF

# Реєстрація OAuth додатка (припускаючи використання django-oauth-toolkit)
echo "Перевірка наявності OAuth додатка..."
python manage.py shell <<EOF
from oauth2_provider.models import Application

if not Application.objects.filter(name='My Application').exists():
    Application.objects.create(
        name='My Application',
        client_type=Application.CLIENT_CONFIDENTIAL,
        authorization_grant_type=Application.GRANT_PASSWORD,
        user=None  # або вкажіть користувача, якщо потрібно
    )
EOF

# Отримання OAuth додатка та збереження client_id та client_secret
echo "Отримання client_id та client_secret..."
APP=$(python manage.py shell -c "from oauth2_provider.models import Application; app = Application.objects.get(name='My Application'); print(app.client_id, app.client_secret)")
CLIENT_ID=$(echo $APP | awk '{print $1}')
CLIENT_SECRET=$(echo $APP | awk '{print $2}')

echo "client_id: $CLIENT_ID"
echo "client_secret: $CLIENT_SECRET"

# Запуск Gunicorn
echo "Запуск Gunicorn..."
exec gunicorn advent_backend.wsgi:application --bind 0.0.0.0:8000