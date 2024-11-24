# Базовий образ
FROM python:3.12-slim

# Встановлення залежностей системи
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Встановлення робочої директорії
WORKDIR /app

# Копіювання файлів проекту
COPY . /app/

# Встановлення права на виконання
RUN chmod +x /app/entrypoint.sh

# Встановлення Python залежностей
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Копіювання скрипту entrypoint
COPY entrypoint.sh /app/

# Встановлення права на виконання (якщо ще не встановлено)
RUN chmod +x /app/entrypoint.sh

# Визначення точки входу
ENTRYPOINT ["/app/entrypoint.sh"]

# Відкриття порту
EXPOSE 8000