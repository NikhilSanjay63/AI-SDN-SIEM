FROM python:3.10-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# Install Python deps (lightweight + stable)
RUN pip install \
    flask \
    numpy \
    joblib \
    scikit-learn \
    tflite-runtime \
    redis

# Copy ALL files from ai-service folder
COPY . .

EXPOSE 5000

CMD ["python", "app.py"]