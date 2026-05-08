import os
import json
import logging
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

print("🚀 AI SERVICE STARTING...")

# -------------------------
# PATH SETUP (VERY IMPORTANT)
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_PATH = os.path.join(BASE_DIR, "model_v2.tflite")
RF_PATH = os.path.join(BASE_DIR, "model_rf.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler_insdn.json")

# -------------------------
# GLOBAL STATE
# -------------------------
interpreter = None
rf_model = None
scaler = None
system_ready = False

# -------------------------
# SAFE LOADING FUNCTION
# -------------------------
def safe_load():
    global interpreter, rf_model, scaler, system_ready

    try:
        # Load scaler
        if os.path.exists(SCALER_PATH):
            with open(SCALER_PATH) as f:
                scaler = json.load(f)
            logging.info("✅ Scaler loaded")
        else:
            logging.warning("⚠️ Scaler missing")

        # Load TFLite model (safe)
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

        # Load RF model (safe)
        try:
            import joblib
            if os.path.exists(RF_PATH):
                rf_model = joblib.load(RF_PATH)
                logging.info("✅ RF model loaded")
            else:
                logging.warning("⚠️ RF model missing")
        except Exception as e:
            logging.warning("⚠️ RF load failed: %s", e)

        system_ready = True
        logging.info("🔥 AI SERVICE READY")

    except Exception as e:
        logging.error("❌ CRITICAL STARTUP ERROR: %s", e)

# Run loader
safe_load()

# -------------------------
# HEALTH CHECK (ALWAYS SAFE)
# -------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "running",
        "system_ready": system_ready,
        "dl_model": interpreter is not None,
        "rf_model": rf_model is not None
    })

# -------------------------
# SAFE PREDICTION (NO CRASH)
# -------------------------
def safe_predict(flow):
    try:
        # fallback if models not loaded
        if interpreter is None and rf_model is None:
            return {
                "prediction": 0,
                "confidence": 0.0,
                "reason": "No model loaded",
                "mitigation": None
            }

        # Simple fallback logic (replace later with real model)
        pkt_count = flow.get("Tot Fwd Pkts", 0)

        if pkt_count > 500:
            return {
                "prediction": 1,
                "confidence": 0.9,
                "reason": "High traffic anomaly",
                "mitigation": {
                    "action": "BLOCK",
                    "target": flow.get("src_ip")
                }
            }

        return {
            "prediction": 0,
            "confidence": 0.8,
            "reason": "Normal traffic",
            "mitigation": None
        }

    except Exception as e:
        logging.error("Prediction error: %s", e)
        return {
            "prediction": 0,
            "confidence": 0.0,
            "reason": "Error fallback",
            "mitigation": None
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
    flows = request.json.get("flows", [])
    results = [safe_predict(flow) for flow in flows]
    return jsonify({"results": results})


# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)