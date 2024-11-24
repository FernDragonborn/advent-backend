# Базовий образ
FROM python:3.12-slim

# Встановлення системних залежностей
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    bash \
    && rm -rf /var/lib/apt/lists/*

# Встановлення робочої директорії
WORKDIR /app

# Копіювання файлів вимог
COPY requirements.txt .

# Встановлення Python залежностей
RUN pip install --upgrade pip && pip install -r requirements.txt

# Копіювання решти файлів проекту
COPY . .

# Встановлення права на виконання для entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Визначення точки входу
#ENTRYPOINT ["/app/entrypoint.sh"]

# Відкриття порту
EXPOSE 8000