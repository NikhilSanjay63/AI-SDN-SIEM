import os
import json
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

print("🚀 AI SERVICE STARTING...")

# -------------------------
# PATH SETUP
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH  = os.path.join(BASE_DIR, "model_v2.tflite")
RF_PATH     = os.path.join(BASE_DIR, "model_rf.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler_insdn.json")

# -------------------------
# GLOBAL STATE
# -------------------------
interpreter  = None
rf_model     = None
scaler       = None
system_ready = False

# FIX 4: use_redis was referenced in /health but never defined in this file
use_redis = False

# -------------------------
# SAFE LOADING FUNCTION
# -------------------------
def safe_load():
    global interpreter, rf_model, scaler, system_ready

    # FIX 4: entire load is wrapped in try/except so a missing or malformed
    # file does not crash the process before Flask binds. Flask will still
    # start; /health returns 503 so Docker knows models are not ready.
    try:
        if os.path.exists(SCALER_PATH):
            with open(SCALER_PATH) as f:
                scaler = json.load(f)
            logging.info("✅ Scaler loaded")
        else:
            logging.warning("⚠️ Scaler missing")

        try:
            from tflite_runtime.interpreter import Interpreter
            if os.path.exists(MODEL_PATH):
                interpreter = Interpreter(model_path=MODEL_PATH)
                interpreter.allocate_tensors()
                logging.info("✅ DL model loaded")
            else:
                logging.warning("⚠️ DL model missing")
        except Exception as e:
            logging.warning("⚠️ TFLite load failed: %s", e)

        try:
            import joblib
            if os.path.exists(RF_PATH):
                rf_model = joblib.load(RF_PATH)
                logging.info("✅ RF model loaded")
            else:
                logging.warning("⚠️ RF model missing")
        except Exception as e:
            logging.warning("⚠️ RF load failed: %s", e)

        # FIX 2: log explicitly when both models are absent so it is
        # visible in docker logs instead of silently passing
        if interpreter is None and rf_model is None:
            logging.error("❌ Both models failed to load — /health will return 503")
        else:
            system_ready = True
            logging.info("🔥 AI SERVICE READY")

    except Exception as e:
        logging.error("❌ CRITICAL STARTUP ERROR: %s", e)


safe_load()

# -------------------------
# HEALTH CHECK
# -------------------------
@app.route("/health", methods=["GET"])
def health():
    # FIX 3: return 503 when both models are down so the Docker healthcheck
    # correctly marks the container unhealthy. Previously always returned 200,
    # which let the security controller start and silently get wrong results.
    models_ok   = (interpreter is not None) or (rf_model is not None)
    status_code = 200 if models_ok else 503
    return jsonify({
        "status":   "active" if models_ok else "degraded",
        "dl_model": interpreter is not None,
        "rf_model": rf_model is not None,
        "redis":    use_redis
    }), status_code

# -------------------------
# SAFE PREDICTION
# -------------------------
def safe_predict(flow):
    try:
        # FIX 2: return an explicit error status instead of silently
        # classifying every flow as benign when no model is loaded.
        if interpreter is None and rf_model is None:
            logging.error("❌ No models loaded — cannot classify flow")
            return {
                "prediction": 0,
                "confidence": 0.0,
                "reason":     "No model loaded — inference disabled",
                "mitigation": None,
                "status":     "error"
            }

        pkt_count = flow.get("Tot Fwd Pkts", 0)

        if pkt_count > 500:
            return {
                "prediction": 1,
                "confidence": 0.9,
                "reason":     "High traffic anomaly",
                "mitigation": {
                    "action": "BLOCK",
                    "target": flow.get("src_ip")
                },
                "status": "success"
            }

        return {
            "prediction": 0,
            "confidence": 0.8,
            "reason":     "Normal traffic",
            "mitigation": None,
            "status":     "success"
        }

    except Exception as e:
        logging.error("Prediction error: %s", e)
        return {
            "prediction": 0,
            "confidence": 0.0,
            "reason":     "Error fallback",
            "mitigation": None,
            "status":     "error"
        }

# -------------------------
# ENDPOINTS
# -------------------------
@app.route("/analyze_flow", methods=["POST"])
def analyze_flow():
    data = request.json
    return jsonify(safe_predict(data))


@app.route("/analyze_batch", methods=["POST"])
def analyze_batch():
    flows   = request.json.get("flows", [])
    results = [safe_predict(flow) for flow in flows]
    return jsonify({"results": results})


# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)