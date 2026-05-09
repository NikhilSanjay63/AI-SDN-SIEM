import os
import json
import logging
import numpy as np
from flask import Flask, request, jsonify
from feature_extractor import FlowFeatureExtractor

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

print("🚀 AI SERVICE STARTING...")

# -------------------------
# PATH SETUP
# -------------------------
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH  = os.path.join(BASE_DIR, "model_v2.tflite")
RF_PATH     = os.path.join(BASE_DIR, "model_rf.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler_insdn.json")

# -------------------------
# CONSTANTS
# -------------------------
TIMESTEPS            = 5
CONFIDENCE_THRESHOLD = 0.60

# -------------------------
# GLOBAL STATE
# -------------------------
interpreter    = None
input_details  = None
output_details = None
rf_model       = None
scaler         = None
system_ready   = False
use_redis      = False

# FIX: import FlowFeatureExtractor so raw flow dicts are properly converted
# into the 24-feature vector the models expect. Previously safe_predict()
# never called the extractor and passed raw dicts directly to placeholder logic.
extractor = FlowFeatureExtractor()

# Per-flow temporal window for LSTM (in-memory, intentional for speed)
flow_buffers = {}

# -------------------------
# SAFE LOADING
# -------------------------
def safe_load():
    global interpreter, input_details, output_details
    global rf_model, scaler, system_ready

    try:
        # Load scaler
        if os.path.exists(SCALER_PATH):
            with open(SCALER_PATH) as f:
                scaler = json.load(f)
            logging.info("✅ Scaler loaded")
        else:
            logging.warning("⚠️ Scaler missing — inference will be disabled")

        # FIX: use tflite_runtime.interpreter not tensorflow, matching
        # what is installed in the Docker image. Previously model_comparison.py
        # used tensorflow directly which is not installed in this container.
        try:
            from tflite_runtime.interpreter import Interpreter
            if os.path.exists(MODEL_PATH):
                interpreter    = Interpreter(model_path=MODEL_PATH)
                interpreter.allocate_tensors()
                input_details  = interpreter.get_input_details()
                output_details = interpreter.get_output_details()
                logging.info("✅ CNN-BiLSTM (TFLite) loaded")
            else:
                logging.warning("⚠️ model_v2.tflite missing")
        except Exception as e:
            logging.warning("⚠️ TFLite load failed: %s", e)

        # Load RF model
        try:
            import joblib
            if os.path.exists(RF_PATH):
                rf_model = joblib.load(RF_PATH)
                logging.info("✅ Random Forest loaded")
            else:
                logging.warning("⚠️ model_rf.pkl missing")
        except Exception as e:
            logging.warning("⚠️ RF load failed: %s", e)

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
    models_ok   = (interpreter is not None) or (rf_model is not None)
    status_code = 200 if models_ok else 503
    return jsonify({
        "status":   "active" if models_ok else "degraded",
        "dl_model": interpreter is not None,
        "rf_model": rf_model is not None,
        "redis":    use_redis
    }), status_code

# -------------------------
# REAL INFERENCE
# -------------------------
def safe_predict(flow):
    """
    Full inference pipeline:
      1. Extract 24-feature vector via FlowFeatureExtractor
      2. Scale using loaded scaler stats
      3. Build LSTM temporal window
      4. Run CNN-BiLSTM; fall back to Random Forest if confidence is low
      5. Return structured result dict
    """
    try:
        # No models or scaler — cannot infer
        if (interpreter is None and rf_model is None) or scaler is None:
            logging.error("❌ No models/scaler loaded — cannot classify flow")
            return {
                "prediction": 0,
                "confidence": 0.0,
                "reason":     "No model loaded — inference disabled",
                "mitigation": None,
                "status":     "error"
            }

        src_ip  = flow.get("src_ip", "UNKNOWN")
        flow_id = flow.get("flow_id", src_ip)

        # FIX: extract features properly using FlowFeatureExtractor instead
        # of the old placeholder that only checked Tot Fwd Pkts > 500.
        feature_vector = extractor.build_vector(flow)

        # FIX: actually use the loaded scaler instead of leaving it idle.
        mins   = np.array(scaler["min"],   dtype=np.float32)
        ranges = np.array(scaler["range"], dtype=np.float32)
        ranges[ranges == 0] = 1.0
        scaled = (feature_vector - mins) / ranges

        # Build temporal window for LSTM
        buffer = flow_buffers.get(flow_id, [])
        buffer.append(scaled[0].tolist())
        if len(buffer) > TIMESTEPS:
            buffer.pop(0)
        flow_buffers[flow_id] = buffer

        curr = np.array(buffer)
        if len(curr) < TIMESTEPS:
            padding    = np.zeros((TIMESTEPS - len(curr), curr.shape[1]), dtype=np.float32)
            lstm_input = np.vstack([padding, curr])
        else:
            lstm_input = curr

        # Run inference
        prediction = 0
        confidence = 0.0
        model_used = "None"
        dl_success = False

        if interpreter is not None:
            inp = np.expand_dims(lstm_input, axis=0).astype(np.float32)
            interpreter.set_tensor(input_details[0]["index"], inp)
            interpreter.invoke()
            output     = interpreter.get_tensor(output_details[0]["index"])[0]
            class_idx  = int(np.argmax(output))
            confidence = float(output[class_idx])
            if confidence >= CONFIDENCE_THRESHOLD:
                prediction = class_idx
                model_used = "CNN-BiLSTM"
                dl_success = True

        if not dl_success and rf_model is not None:
            flat       = scaled.reshape(1, -1)
            prediction = int(rf_model.predict(flat)[0])
            try:
                confidence = float(max(rf_model.predict_proba(flat)[0]))
            except Exception:
                confidence = 1.0
            model_used = "RandomForest"

        mitigation = None
        if prediction == 1:
            mitigation = {
                "action":   "BLOCK",
                "target":   src_ip,
                "priority": 100
            }
            logging.warning("🚨 ATTACK | src=%s | model=%s | conf=%.2f",
                            src_ip, model_used, confidence)
        else:
            logging.info("✅ NORMAL | src=%s | model=%s | conf=%.2f",
                         src_ip, model_used, confidence)

        return {
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "model_used": model_used,
            "reason":     "Attack detected" if prediction == 1 else "Normal traffic",
            "mitigation": mitigation,
            "status":     "success"
        }

    except Exception as e:
        logging.error("❌ Prediction error: %s", e)
        return {
            "prediction": 0,
            "confidence": 0.0,
            "reason":     "Inference error: {}".format(str(e)),
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