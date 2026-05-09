FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# FIX: pin all versions
# numpy==1.26.4     — REQUIRED for sklearn pickle compatibility
# scikit-learn==1.6.1 — must match version used when model_rf.pkl was trained
# tflite-runtime    — lightweight TFLite only; no full tensorflow needed
# curl              — REQUIRED by docker-compose healthcheck (was missing)
RUN pip install --upgrade pip && pip install --no-cache-dir \
    flask==3.0.3 \
    numpy==1.26.4 \
    joblib==1.4.2 \
    scikit-learn==1.6.1 \
    tflite-runtime==2.14.0 \
    redis==5.0.4

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]