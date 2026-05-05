"""
app.py  —  IMPROVED VERSION
============================
Improvements over original:
  1. /analyze_batch endpoint  : Accepts a list of flows in one request and
                                returns a list of results — one per flow.
                                Reduces REST call overhead by up to BATCH_SIZE×.
  2. Redis blacklist check    : Flows from already-blocked IPs are short-circuited
                                immediately without model inference.
  3. /analyze_flow kept       : The original single-flow endpoint is preserved for
                                backward compatibility and local testing.
"""

import flask
from flask import request, jsonify
import numpy as np
import tensorflow as tf
import joblib
import json
import logging
import os
import redis
from datetime import datetime
from feature_extractor import FlowFeatureExtractor

# ══════════════════════════════════════════════════════
#  1. LOGGING
# ══════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

app = flask.Flask(__name__)

# ══════════════════════════════════════════════════════
#  2. CONSTANTS
# ══════════════════════════════════════════════════════
MODEL_DL_PATH = "model_v2.tflite"
MODEL_RF_PATH = "model_rf.pkl"
SCALER_PATH   = "scaler_insdn.json"

TIMESTEPS            = 5
CONFIDENCE_THRESHOLD = 0.60
SIEM_LOG_FILE        = "/var/log/siem_events.log"

# Redis
REDIS_HOST    = "redis-db"
REDIS_PORT    = 6379
BLACKLIST_TTL = 600   # seconds — mirrors hard_timeout in controller

# ══════════════════════════════════════════════════════
#  3. GLOBAL STATE
# ══════════════════════════════════════════════════════
extractor      = FlowFeatureExtractor()
interpreter    = None
rf_model       = None
scaler_stats   = None
input_details  = None
output_details = None
flow_buffers   = {}   # per-flow temporal window (in-memory, intentional for speed)

# Redis connection — graceful fallback
try:
    redis_client = redis.Redis(
        host=REDIS_HOST, port=REDIS_PORT,
        decode_responses=True, socket_connect_timeout=2
    )
    redis_client.ping()
    use_redis = True
    logging.info("✅ Redis connected")
except Exception as e:
    logging.warning("⚠️  Redis unavailable (%s) — blacklist disabled", e)
    redis_client = None
    use_redis    = False

# ══════════════════════════════════════════════════════
#  4. SIEM EVENT WRITER
# ══════════════════════════════════════════════════════
def write_siem_event(src_ip, dst_ip, attack_type, confidence, action, model_used):
    event = {
        "timestamp":       datetime.utcnow().isoformat(),
        "source_ip":       src_ip,
        "destination_ip":  dst_ip,
        "attack_type":     attack_type,
        "confidence":      round(confidence, 3),
        "action":          action,
        "severity":        "HIGH",
        "detected_by":     "AI-IDS",
        "model_used":      model_used
    }
    try:
        with open(SIEM_LOG_FILE, "a") as f:
            f.write(json.dumps(event) + "\n")
        logging.info("🧾 SIEM event written")
    except Exception as e:
        logging.error("❌ Failed to write SIEM event: %s", e)

# ══════════════════════════════════════════════════════
#  5. REDIS BLACKLIST HELPERS
# ══════════════════════════════════════════════════════
def is_blacklisted(ip: str) -> bool:
    """Return True if this IP is already in the Redis block-list."""
    if not use_redis:
        return False
    return bool(redis_client.exists(f"blacklist:{ip}"))

def add_to_blacklist(ip: str):
    """Add an IP to Redis blacklist with TTL matching the OpenFlow hard_timeout."""
    if not use_redis:
        return
    redis_client.setex(f"blacklist:{ip}", BLACKLIST_TTL, "1")
    logging.info("🔴 IP added to Redis blacklist: %s (TTL=%ss)", ip, BLACKLIST_TTL)

# ══════════════════════════════════════════════════════
#  6. LOAD MODELS & SCALER
# ══════════════════════════════════════════════════════
def load_system():
    global interpreter, rf_model, scaler_stats, input_details, output_details

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("Scaler file missing: " + SCALER_PATH)

    with open(SCALER_PATH) as f:
        scaler_stats = json.load(f)
    logging.info("✅ Scaler loaded")

    try:
        interpreter = tf.lite.Interpreter(model_path=MODEL_DL_PATH)
        interpreter.allocate_tensors()
        input_details  = interpreter.get_input_details()
        output_details = interpreter.get_output_details()
        logging.info("✅ CNN-BiLSTM loaded")
    except Exception as e:
        logging.error("❌ DL model failed: %s", e)
        interpreter = None

    try:
        rf_model = joblib.load(MODEL_RF_PATH)
        logging.info("✅ Random Forest loaded")
    except Exception as e:
        logging.warning("⚠️  RF model disabled: %s", e)
        rf_model = None

load_system()

# ══════════════════════════════════════════════════════
#  7. CORE INFERENCE FUNCTION  (shared by both endpoints)
# ══════════════════════════════════════════════════════
def _get_flow_buffer(flow_id: str) -> list:
    """Load temporal buffer for a flow from Redis or memory."""
    if use_redis:
        raw = redis_client.get(f"buffer:{flow_id}")
        return json.loads(raw) if raw else []
    return flow_buffers.get(flow_id, [])

def _save_flow_buffer(flow_id: str, buffer: list):
    """Save temporal buffer for a flow to Redis or memory."""
    if use_redis:
        # Buffer expires if no new packets for 1 hour
        redis_client.setex(f"buffer:{flow_id}", 3600, json.dumps(buffer))
    else:
        flow_buffers[flow_id] = buffer

def _infer_single(flow_data: dict) -> dict:
    """
    Run inference on a single flow dict.
    Returns a result dict identical in shape to what /analyze_flow used to return.
    """
    flow_id = flow_data.get("flow_id", "unknown")
    src_ip  = flow_data.get("src_ip",  "UNKNOWN")
    dst_ip  = flow_data.get("dst_ip",  "UNKNOWN")

    # ── Redis blacklist short-circuit ────────────────────────────────────────
    if is_blacklisted(src_ip):
        logging.info("⚡ Blacklist hit — skipping inference for %s", src_ip)
        return {
            "flow_id":    flow_id,
            "prediction": 1,
            "confidence": 1.0,
            "model_used": "Blacklist-Cache",
            "reason":     "Previously confirmed attacker",
            "mitigation": {"action": "BLOCK", "target": src_ip,
                           "priority": 100, "idle_timeout": 300, "hard_timeout": 600},
            "status":     "blacklisted"
        }

    # ── Feature extraction & scaling ─────────────────────────────────────────
    feature_vector = extractor.build_vector(flow_data)

    mins   = np.array(scaler_stats["min"],   dtype=np.float32)
    ranges = np.array(scaler_stats["range"], dtype=np.float32)
    ranges[ranges == 0] = 1.0
    scaled = (feature_vector - mins) / ranges

    # ── Temporal window (per flow_id) ─────────────────────────────────────────
    buffer = _get_flow_buffer(flow_id)
    buffer.append(scaled[0].tolist())
    if len(buffer) > TIMESTEPS:
        buffer.pop(0)
    _save_flow_buffer(flow_id, buffer)

    curr = np.array(buffer)
    if len(curr) < TIMESTEPS:
        padding    = np.zeros((TIMESTEPS - len(curr), curr.shape[1]), dtype=np.float32)
        lstm_input = np.vstack([padding, curr])
    else:
        lstm_input = curr

    # ── Inference ─────────────────────────────────────────────────────────────
    prediction = 0
    confidence = 0.0
    model_used = "None"
    reason     = "N/A"
    dl_success = False

    if interpreter is not None:
        inp = np.expand_dims(lstm_input, axis=0).astype(np.float32)
        interpreter.set_tensor(input_details[0]["index"], inp)
        interpreter.invoke()
        output    = interpreter.get_tensor(output_details[0]["index"])[0]
        class_idx = int(np.argmax(output))
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

    # ── Mitigation decision ───────────────────────────────────────────────────
    mitigation = None

    if prediction == 1:
        pkt_rate = feature_vector[0][6]
        syn_cnt  = feature_vector[0][14]

        if pkt_rate > 1000:
            reason = "High Packet Rate (DoS)"
        elif syn_cnt > 50:
            reason = "SYN Flood"
        else:
            reason = "Malicious Flow Pattern"

        mitigation = {
            "action":       "BLOCK",
            "target":       src_ip,
            "priority":     100,
            "idle_timeout": 300,
            "hard_timeout": 600
        }

        # Persist to Redis blacklist so future flows skip inference
        add_to_blacklist(src_ip)

        write_siem_event(
            src_ip=src_ip, dst_ip=dst_ip,
            attack_type=reason, confidence=confidence,
            action="BLOCK", model_used=model_used
        )

        logging.warning("🚨 ATTACK detected | src=%s | reason=%s | model=%s | conf=%.2f",
                        src_ip, reason, model_used, confidence)
    else:
        logging.info("✅ NORMAL | src=%s | model=%s | conf=%.2f", src_ip, model_used, confidence)

    return {
        "flow_id":    flow_id,
        "prediction": prediction,
        "confidence": round(confidence, 4),
        "model_used": model_used,
        "reason":     reason,
        "mitigation": mitigation,
        "status":     "success"
    }

# ══════════════════════════════════════════════════════
#  8. HEALTH CHECK
# ══════════════════════════════════════════════════════
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":    "active",
        "dl_model":  interpreter is not None,
        "rf_model":  rf_model is not None,
        "redis":     use_redis
    })

# ══════════════════════════════════════════════════════
#  9. SINGLE-FLOW ENDPOINT  (original — preserved)
# ══════════════════════════════════════════════════════
@app.route("/analyze_flow", methods=["POST"])
def analyze_flow():
    logging.info("📥 /analyze_flow request received")
    if not request.json:
        return jsonify({"error": "Missing JSON body"}), 400
    try:
        return jsonify(_infer_single(request.json))
    except Exception as e:
        logging.error("❌ /analyze_flow error: %s", e)
        return jsonify({"error": "Internal Error", "details": str(e)}), 500

# ══════════════════════════════════════════════════════
#  10. BATCH ENDPOINT  (new — called by improved controller)
# ══════════════════════════════════════════════════════
@app.route("/analyze_batch", methods=["POST"])
def analyze_batch():
    """
    Accepts:
        { "flows": [ <flow_dict>, <flow_dict>, ... ] }

    Returns:
        { "results": [ <result_dict>, <result_dict>, ... ] }

    One result per flow, in the same order.
    Reduces per-flow HTTP overhead by processing up to BATCH_SIZE flows
    in a single round-trip between the controller and the AI service.
    """
    logging.info("📦 /analyze_batch request received")

    if not request.json or "flows" not in request.json:
        return jsonify({"error": "Missing 'flows' list in JSON body"}), 400

    flows = request.json["flows"]
    if not isinstance(flows, list) or len(flows) == 0:
        return jsonify({"error": "'flows' must be a non-empty list"}), 400

    results = []
    for flow_data in flows:
        try:
            results.append(_infer_single(flow_data))
        except Exception as e:
            logging.error("❌ Batch item error: %s", e)
            results.append({
                "flow_id":    flow_data.get("flow_id", "unknown"),
                "prediction": 0,
                "confidence": 0.0,
                "model_used": "Error",
                "reason":     str(e),
                "mitigation": None,
                "status":     "error"
            })

    logging.info("📦 Batch processed: %d flows, %d attacks",
                 len(results), sum(1 for r in results if r["prediction"] == 1))

    return jsonify({"results": results})

# ══════════════════════════════════════════════════════
#  11. RUN
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)