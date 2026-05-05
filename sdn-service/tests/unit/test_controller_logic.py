import unittest
import sys
import os
import math

# Mock Ryu environment before importing the controller
class MockRyuApp:
    def __init__(self, *args, **kwargs): pass
    @staticmethod
    def _get_logger():
        import logging
        return logging.getLogger("mock")
    logger = _get_logger()

import ryu.base.app_manager
ryu.base.app_manager.RyuApp = MockRyuApp

# Now import the controller
sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from controllers.security_controller import SecurityController

class TestSecurityController(unittest.TestCase):
    def setUp(self):
        # We don't want to actually connect to Redis during unit tests
        SecurityController.__init__ = lambda self: None
        self.controller = SecurityController()
        
    def test_payload_construction(self):
        # Mock a flow object
        flow = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "start": 1000.0,
            "last": 1001.0,
            "iat": [0.1, 0.2, 0.3],
            "pkt_sizes": [60, 100, 140],
            "fwd_pkts": 3,
            "fwd_bytes": 300,
            "protocol": 6,
            "src_port": 1234,
            "dst_port": 80,
            "flags": {"SYN": 1, "ACK": 2, "RST": 0, "PSH": 0, "URG": 0}
        }
        
        payload = self.controller._build_payload(flow)
        
        self.assertEqual(payload["src_ip"], "10.0.0.1")
        self.assertEqual(payload["Flow Duration"], 1.0)
        self.assertAlmostEqual(payload["Flow IAT Mean"], 0.2)
        self.assertEqual(payload["Tot Fwd Pkts"], 3)
        self.assertEqual(payload["SYN Flag Cnt"], 1)
        self.assertEqual(payload["ACK Flag Cnt"], 2)

if __name__ == "__main__":
    unittest.main()
