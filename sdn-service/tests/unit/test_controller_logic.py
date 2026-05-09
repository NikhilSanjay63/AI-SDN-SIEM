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

sys.path.append(os.path.join(os.path.dirname(__file__), '../../'))
from controllers.security_controller import SecurityController

class TestSecurityController(unittest.TestCase):
    def setUp(self):
        SecurityController.__init__ = lambda self: None
        self.controller = SecurityController()

    def test_payload_construction(self):
        flow = {
            "src_ip":   "10.0.0.1",
            # FIX: dst_ip was missing from the test flow dict. _build_payload()
            # uses flow.get("dst_ip", "UNKNOWN"), so flow_id was silently built
            # with "UNKNOWN" instead of a real IP — not matching real traffic.
            "dst_ip":   "10.0.0.2",
            "start":    1000.0,
            "last":     1001.0,
            "iat":      [0.1, 0.2, 0.3],
            "pkt_sizes":[60, 100, 140],
            "fwd_pkts": 3,
            "fwd_bytes":300,
            "protocol": 6,
            "src_port": 1234,
            "dst_port": 80,
            "flags":    {"SYN": 1, "ACK": 2, "RST": 0, "PSH": 0, "URG": 0}
        }

        payload = self.controller._build_payload(flow)

        self.assertEqual(payload["src_ip"], "10.0.0.1")
        self.assertEqual(payload["dst_ip"], "10.0.0.2")
        self.assertEqual(payload["Flow Duration"], 1.0)
        self.assertAlmostEqual(payload["Flow IAT Mean"], 0.2)
        self.assertEqual(payload["Tot Fwd Pkts"], 3)
        self.assertEqual(payload["SYN Flag Cnt"], 1)
        self.assertEqual(payload["ACK Flag Cnt"], 2)

        # FIX: verify flow_id is now a proper 5-tuple string and not just src_ip.
        # Previously flow_id was set to src_ip alone, causing flows from the
        # same source to share an LSTM buffer and corrupt each other's inference.
        expected_flow_id = "10.0.0.1-10.0.0.2-1234-80-6"
        self.assertEqual(payload["flow_id"], expected_flow_id)

    def test_payload_missing_dst_ip_fallback(self):
        # Verify that a flow without dst_ip doesn't crash and uses "UNKNOWN"
        flow = {
            "src_ip":   "10.0.0.1",
            "start":    1000.0,
            "last":     1001.0,
            "iat":      [],
            "pkt_sizes":[64],
            "fwd_pkts": 1,
            "fwd_bytes":64,
            "protocol": 17,
            "src_port": 5000,
            "dst_port": 53,
            "flags":    {"SYN": 0, "ACK": 0, "RST": 0, "PSH": 0, "URG": 0}
        }
        payload = self.controller._build_payload(flow)
        self.assertIn("UNKNOWN", payload["flow_id"])
        self.assertEqual(payload["dst_ip"], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()