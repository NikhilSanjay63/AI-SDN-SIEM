import os
import json
import time
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
SIEM_LOG    = "/var/log/siem_events.log"

# -------------------------
# CONSTANTS
# -------------------------
TIMESTEPS            = 5
CONFIDENCE_THRESHOLD = 0.60
BLACKLIST_TTL        = 600   # seconds — mirrors OpenFlow hard_timeout
BUFFER_TTL           = 3600  # seconds — expire idle flow LSTM buffers

# -------------------------
# REDIS SETUP
# FIX: REDIS_HOST and REDIS_PORT were set as environment variables in
# docker-compose.yml but app.py never read them — use_redis was hardcoded
# to False. Redis integration (blacklist checks, buffer persistence) was
# completely absent. Now reads env vars and connects properly.
# -------------------------
REDIS_HOST = os.environ.get("REDIS_HOST", "redis-db")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))

redis_client = None
use_redis    = False

try:
    import redis as redis_lib
    redis_client = redis_lib.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        decode_responses=True, socket_connect_timeout=3
    )
    redis_client.ping()
    use_redis = True
    logging.info("✅ Redis connected at %s:%s", REDIS_HOST, REDIS_PORT)
except Exception as e:
    logging.warning("⚠️ Redis unavailable (%s) — blacklist and buffer persistence disabled", e)

# -------------------------
# GLOBAL STATE
# -------------------------
interpreter    = None
input_details  = None
output_details = None
rf_model       = None
scaler         = None
system_ready   = False
extractor      = FlowFeatureExtractor()

# FIX: flow_buffers previously grew forever — one entry per unique flow_id,
# never cleaned up. Under real traffic this is an unbounded memory leak.
# Now each entry also stores a last_seen timestamp so a background sweep
# (called lazily on each predict) can evict entries idle for > BUFFER_TTL.
flow_buffers = {}   # { flow_id: {"buffer": [...], "ts": float} }

# -------------------------
# SAFE LOADING
# -------------------------
def safe_load():
    global interpreter, input_details, output_details
    global rf_model, scaler, system_ready

    try:
        if os.path.exists(SCALER_PATH):
            with open(SCALER_PATH) as f:
                scaler = json.load(f)
            logging.info("✅ Scaler loaded")
        else:
            logging.warning("⚠️ Scaler missing — inference will be disabled")

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
# REDIS HELPERS
# -------------------------
def is_blacklisted(ip):
    if not use_redis:
        return False
    try:
        return bool(redis_client.exists("blacklist:{}".format(ip)))
    except Exception as e:
        logging.warning("⚠️ Redis blacklist check failed: %s", e)
        return False

def add_to_blacklist(ip):
    if not use_redis:
        return
    try:
        redis_client.setex("blacklist:{}".format(ip), BLACKLIST_TTL, "1")
        logging.info("🔴 Blacklisted %s (TTL=%ss)", ip, BLACKLIST_TTL)
    except Exception as e:
        logging.warning("⚠️ Redis blacklist write failed: %s", e)

# -------------------------
# FLOW BUFFER HELPERS
# FIX: LSTM buffers are now stored in Redis when available (survives restarts)
# and cleaned up by TTL. In-memory fallback evicts idle entries lazily.
# -------------------------
def _evict_stale_buffers():
    """Remove in-memory buffers idle for longer than BUFFER_TTL."""
    now  = time.time()
    dead = [fid for fid, v in flow_buffers.items()
            if now - v["ts"] > BUFFER_TTL]
    for fid in dead:
        del flow_buffers[fid]
    if dead:
        logging.info("🧹 Evicted %d stale flow buffers", len(dead))

def get_flow_buffer(flow_id):
    if use_redis:
        try:
            raw = redis_client.get("buffer:{}".format(flow_id))
            return json.loads(raw) if raw else []
        except Exception:
            pass
    entry = flow_buffers.get(flow_id)
    return entry["buffer"] if entry else []

def save_flow_buffer(flow_id, buffer):
    if use_redis:
        try:
            redis_client.setex(
                "buffer:{}".format(flow_id), BUFFER_TTL,
                json.dumps(buffer)
            )
            return
        except Exception:
            pass
    flow_buffers[flow_id] = {"buffer": buffer, "ts": time.time()}

# -------------------------
# SIEM WRITER
# -------------------------
def write_siem_event(src_ip, dst_ip, attack_type, confidence, model_used):
    event = {
        "timestamp":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_ip":      src_ip,
        "destination_ip": dst_ip,
        "attack_type":    attack_type,
        "confidence":     round(confidence, 3),
        "action":         "BLOCK",
        "severity":       "HIGH",
        "detected_by":    "AI-IDS",
        "model_used":     model_used
    }
    try:
        with open(SIEM_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")
        logging.info("🧾 SIEM event written")
    except Exception as e:
        logging.error("❌ SIEM write failed: %s", e)

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
# INFERENCE
# -------------------------
def safe_predict(flow):
    try:
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
        dst_ip  = flow.get("dst_ip", "UNKNOWN")
        flow_id = flow.get("flow_id", src_ip)

        # FIX: check Redis blacklist before running inference —
        # previously this entire check was missing from this version of app.py.
        if is_blacklisted(src_ip):
            logging.info("⚡ Blacklist hit — skipping inference for %s", src_ip)
            return {
                "prediction": 1,
                "confidence": 1.0,
                "model_used": "Blacklist-Cache",
                "reason":     "Previously confirmed attacker",
                "mitigation": {"action": "BLOCK", "target": src_ip, "priority": 100},
                "status":     "blacklisted"
            }

        # Evict stale in-memory buffers lazily (no-op when Redis is active)
        if not use_redis:
            _evict_stale_buffers()

        feature_vector = extractor.build_vector(flow)

        mins   = np.array(scaler["min"],   dtype=np.float32)
        ranges = np.array(scaler["range"], dtype=np.float32)
        ranges[ranges == 0] = 1.0
        scaled = (feature_vector - mins) / ranges

        # Build LSTM temporal window
        buffer = get_flow_buffer(flow_id)
        buffer.append(scaled[0].tolist())
        if len(buffer) > TIMESTEPS:
            buffer.pop(0)
        save_flow_buffer(flow_id, buffer)

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
            mitigation = {"action": "BLOCK", "target": src_ip, "priority": 100}
            add_to_blacklist(src_ip)
            write_siem_event(src_ip, dst_ip, "Attack detected", confidence, model_used)
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
    return jsonify(safe_predict(request.json))


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