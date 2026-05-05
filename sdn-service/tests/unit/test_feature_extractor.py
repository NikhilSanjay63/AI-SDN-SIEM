import unittest
import numpy as np
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '../../ai-service'))
from feature_extractor import FlowFeatureExtractor

class TestFeatureExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = FlowFeatureExtractor()
        
    def test_vector_shape(self):
        sample_flow = {"Tot Fwd Pkts": 10, "TotLen Fwd Pkts": 1000}
        vector = self.extractor.build_vector(sample_flow)
        self.assertEqual(vector.shape, (1, 24))
        
    def test_packet_rate_calculation(self):
        sample_flow = {
            "Tot Fwd Pkts": 100,
            "Flow Duration": 2.0
        }
        vector = self.extractor.build_vector(sample_flow)
        # Packet Rate is index 6
        self.assertEqual(vector[0][6], 50.0)
        
    def test_missing_features_defaults(self):
        # Empty dict should not crash and should return 0s for missing metrics
        vector = self.extractor.build_vector({})
        self.assertEqual(vector[0][0], 1e-6) # Duration defaults to epsilon
        self.assertEqual(vector[0][7], 0)    # Tot Fwd Pkts defaults to 0

if __name__ == "__main__":
    unittest.main()
