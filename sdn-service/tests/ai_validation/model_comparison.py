import numpy as np
import joblib
import json
import os
import sys

# FIX: replaced "import tensorflow as tf" + tf.lite.Interpreter with
# tflite_runtime.interpreter. tensorflow is not installed in the ai-service
# container (only tflite-runtime is), so the old import crashed immediately
# with ModuleNotFoundError before any test ran.
from tflite_runtime.interpreter import Interpreter

sys.path.append(os.path.join(os.path.dirname(__file__), '../../ai-service'))
from feature_extractor import FlowFeatureExtractor

# FIX: replaced relative ../../ai-service/ paths with paths relative to
# /app (the container WORKDIR). The old paths resolved correctly on the host
# but pointed outside /app inside the container, causing FileNotFoundError.
# Now supports both: container execution (paths from /app) and host execution
# (paths relative to this file's location).
_THIS_DIR    = os.path.dirname(os.path.abspath(__file__))
_AI_DIR_HOST = os.path.join(_THIS_DIR, '../../ai-service')
_AI_DIR_CONT = '/app'

# Use container path if running inside Docker, host path otherwise
_AI_DIR = _AI_DIR_CONT if os.path.exists('/app/model_v2.tflite') else _AI_DIR_HOST

MODEL_DL_PATH = os.path.join(_AI_DIR, 'model_v2.tflite')
MODEL_RF_PATH = os.path.join(_AI_DIR, 'model_rf.pkl')
SCALER_PATH   = os.path.join(_AI_DIR, 'scaler_insdn.json')


def test_models():
    print("🧠 Starting Model Comparison Test")

    # Load scaler
    with open(SCALER_PATH) as f:
        scaler = json.load(f)
    mins   = np.array(scaler["min"],   dtype=np.float32)
    ranges = np.array(scaler["range"], dtype=np.float32)
    ranges[ranges == 0] = 1.0

    # Load TFLite model
    interpreter    = Interpreter(model_path=MODEL_DL_PATH)
    interpreter.allocate_tensors()
    input_details  = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    # Load RF model
    rf_model = joblib.load(MODEL_RF_PATH)

    extractor = FlowFeatureExtractor()

    test_cases = [
        {
            "name": "Normal Traffic",
            "data": {
                "Flow Duration": 1.0, "Flow IAT Mean": 0.2,
                "Tot Fwd Pkts": 5, "TotLen Fwd Pkts": 300,
                "Protocol": 6, "Src Port": 443, "Dst Port": 1234,
                "SYN Flag Cnt": 1, "ACK Flag Cnt": 4
            },
            "expected": 0
        },
        {
            "name": "DoS Attack (High Rate)",
            "data": {
                "Flow Duration": 0.001, "Flow IAT Mean": 0.0001,
                "Tot Fwd Pkts": 1000, "TotLen Fwd Pkts": 64000,
                "Protocol": 1, "Src Port": 0, "Dst Port": 0,
                "SYN Flag Cnt": 0, "ACK Flag Cnt": 0
            },
            "expected": 1
        }
    ]

    for case in test_cases:
        print("\nTesting: {}".format(case["name"]))

        features = extractor.build_vector(case["data"])
        scaled   = (features - mins) / ranges

        # RF prediction
        rf_pred = rf_model.predict(scaled.reshape(1, -1))[0]
        rf_conf = max(rf_model.predict_proba(scaled.reshape(1, -1))[0])
        print("  [RandomForest] Prediction: {} | Confidence: {:.4f}".format(rf_pred, rf_conf))

        # CNN-BiLSTM prediction (repeat single frame × TIMESTEPS to mock sequence)
        lstm_input = np.tile(scaled, (5, 1)).astype(np.float32)
        inp        = np.expand_dims(lstm_input, axis=0)
        interpreter.set_tensor(input_details[0]["index"], inp)
        interpreter.invoke()
        output  = interpreter.get_tensor(output_details[0]["index"])[0]
        dl_pred = int(np.argmax(output))
        dl_conf = float(output[dl_pred])
        print("  [CNN-BiLSTM]  Prediction: {} | Confidence: {:.4f}".format(dl_pred, dl_conf))

        if dl_pred == case["expected"] or rf_pred == case["expected"]:
            print("  ✅ TEST PASSED")
        else:
            print("  ❌ TEST FAILED")


if __name__ == "__main__":
    test_models()