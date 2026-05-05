import numpy as np
import tensorflow as tf
import joblib
import json
import os
import sys

# Add ai-service to path to import feature extractor
sys.path.append(os.path.join(os.path.dirname(__file__), '../../ai-service'))
from feature_extractor import FlowFeatureExtractor

# Paths
MODEL_DL_PATH = "../../ai-service/model_v2.tflite"
MODEL_RF_PATH = "../../ai-service/model_rf.pkl"
SCALER_PATH   = "../../ai-service/scaler_insdn.json"

def test_models():
    print("🧠 Starting Model Comparison Test")
    
    # Load Scaler
    with open(SCALER_PATH) as f:
        scaler = json.load(f)
    mins = np.array(scaler["min"], dtype=np.float32)
    ranges = np.array(scaler["range"], dtype=np.float32)
    ranges[ranges == 0] = 1.0
    
    # Load DL Model
    interpreter = tf.lite.Interpreter(model_path=MODEL_DL_PATH)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()
    
    # Load RF Model
    rf_model = joblib.load(MODEL_RF_PATH)
    
    extractor = FlowFeatureExtractor()
    
    # Test cases: Normal vs Attack
    test_cases = [
        {
            "name": "Normal Traffic",
            "data": {
                "Flow Duration": 1.0, "Flow IAT Mean": 0.2, "Tot Fwd Pkts": 5, "TotLen Fwd Pkts": 300,
                "Protocol": 6, "Src Port": 443, "Dst Port": 1234, "SYN Flag Cnt": 1, "ACK Flag Cnt": 4
            },
            "expected": 0
        },
        {
            "name": "DoS Attack (High Rate)",
            "data": {
                "Flow Duration": 0.001, "Flow IAT Mean": 0.0001, "Tot Fwd Pkts": 1000, "TotLen Fwd Pkts": 64000,
                "Protocol": 1, "Src Port": 0, "Dst Port": 0, "SYN Flag Cnt": 0, "ACK Flag Cnt": 0
            },
            "expected": 1
        }
    ]
    
    for case in test_cases:
        print(f"\nTesting: {case['name']}")
        
        # 1. Feature Extraction
        features = extractor.build_vector(case['data'])
        scaled = (features - mins) / ranges
        
        # 2. RF Prediction
        rf_pred = rf_model.predict(scaled.reshape(1, -1))[0]
        rf_conf = max(rf_model.predict_proba(scaled.reshape(1, -1))[0])
        print(f"  [RandomForest] Prediction: {rf_pred} | Confidence: {rf_conf:.4f}")
        
        # 3. DL Prediction (CNN-BiLSTM)
        # Note: We need a sequence of 5 for BiLSTM, we'll mock it by repeating the same vector
        lstm_input = np.tile(scaled, (5, 1)).astype(np.float32)
        inp = np.expand_dims(lstm_input, axis=0)
        interpreter.set_tensor(input_details[0]["index"], inp)
        interpreter.invoke()
        output = interpreter.get_tensor(output_details[0]["index"])[0]
        dl_pred = np.argmax(output)
        dl_conf = output[dl_pred]
        print(f"  [CNN-BiLSTM]  Prediction: {dl_pred} | Confidence: {dl_conf:.4f}")
        
        if dl_pred == case['expected'] or rf_pred == case['expected']:
            print("  ✅ TEST PASSED")
        else:
            print("  ❌ TEST FAILED")

if __name__ == "__main__":
    test_models()
