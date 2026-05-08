FROM python:3.10-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# System deps (minimal but sufficient)
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip

# -------------------------------
# CRITICAL VERSION PINNING
# -------------------------------
# NumPy 1.26.4 → REQUIRED for sklearn pickles
# sklearn 1.6.1 → matches RF model
# tensorflow → CPU-only auto on all platforms
# -------------------------------
RUN pip install --no-cache-dir \
    flask \
    numpy==1.26.4 \
    scikit-learn==1.6.1 \
    tensorflow \
    joblib \
    redis

# Copy application files (context is sdn-service/)
COPY ai-service/app.py .
COPY ai-service/feature_extractor.py .
COPY ai-service/model_v2.tflite .
COPY ai-service/model_rf.pkl .
COPY ai-service/scaler_insdn.json .

# Copy tests
COPY tests/ /app/tests/

EXPOSE 5000

# Use gunicorn for faster startup signal handling
CMD ["python", "app.py"]