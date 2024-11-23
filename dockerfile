# Dockerfile

# Використовуємо офіційний Python образ як базовий
FROM python:3.12-slim

# Встановлюємо змінні середовища для покращення безпеки та продуктивності
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Встановлюємо робочу директорію
WORKDIR /app

# Встановлюємо системні залежності
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Копіюємо файл вимог і встановлюємо залежності
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Копіюємо решту коду додатку
COPY . /app/
COPY .env /app/

# Збираємо статичні файли
RUN python manage.py collectstatic --noinput

# Відкриваємо порт 8000
EXPOSE 8000

# Вказуємо команду для запуску Gunicorn
CMD ["gunicorn", "advent_backend.wsgi:application", "--bind", "0.0.0.0:8000"]
