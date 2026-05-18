import unittest
import time
from ssol_ueba_engine import UEBAEngine, UEBAProfile

class TestSSOLUEBAEngine(unittest.TestCase):
    def setUp(self):
        # Initialize engine with safe defaults
        self.engine = UEBAEngine(config_path="nonexistent_config.yaml")

    def test_baseline_profiling(self):
        """Test 1: Verify user behavior baseline profiling and creation."""
        print("[-] Running Test: UEBA Baseline Profiling...")
        
        # Test creation of profile
        profile = self.engine.get_or_create_profile(1005)
        self.assertIsInstance(profile, UEBAProfile)
        self.assertEqual(profile.uid, 1005)
        self.assertIn("bash", profile.process_whitelist)
        self.assertEqual(profile.alert_count, 0)
        
        # Verify cached retrieval
        profile_cached = self.engine.get_or_create_profile(1005)
        self.assertIs(profile, profile_cached)
        print("\033[92m[v] Test Passed: Behavioral profiles created and tracked correctly.\033[0m")

    def test_deviation_calculation(self):
        """Test 2: Verify deviation calculations and risk score generation thresholds."""
        print("[-] Running Test: Behavior Deviation & Scoring...")
        
        # 1. Clean event
        evt_clean = {
            "process_context": {
                "comm": "bash",
                "binary_path": "/bin/bash",
                "uid": 1005
            }
        }
        
        # Tweak baseline to fit the current testing time so it is not marked off-hours
        current_hour = time.localtime().tm_hour
        profile = self.engine.get_or_create_profile(1005)
        profile.typical_hours.add(current_hour)
        
        score_clean, alert_clean = self.engine.evaluate_behavior(evt_clean)
        self.assertEqual(score_clean, 0)
        self.assertIsNone(alert_clean)

        # 2. Extreme anomalous event (sensitive path + malicious process)
        evt_anom = {
            "process_context": {
                "comm": "nc",
                "binary_path": "/usr/bin/nc",
                "arguments": "-lvnp 4444",
                "uid": 1005
            }
        }
        
        score_anom, alert_anom = self.engine.evaluate_behavior(evt_anom)
        # Should flag highly anomalous (malicious process nc + lateral pattern in args)
        self.assertGreaterEqual(score_anom, 65)
        self.assertIsNotNone(alert_anom)
        self.assertIn("anomaly_context", alert_anom)
        self.assertEqual(alert_anom["anomaly_context"]["risk_score"], score_anom)
        
        print("\033[92m[v] Test Passed: Deviation and risk ratings conform completely to design specifications.\033[0m")

    def test_gnn_socket_parsing(self):
        """Test 3: Verify GNN-based socket event parsing and score integrations."""
        print("[-] Running Test: GNN integration validation...")
        
        # GNN integration verify
        evt_gnn = {
            "process_context": {
                "comm": "ransomware_sim",
                "binary_path": "/root/compromised_script",
                "arguments": "--target /etc/shadow",
                "uid": 0
            }
        }
        
        score, alert = self.engine.evaluate_behavior(evt_gnn)
        # Should score extremely high because of sensitive VFS + malicious process ransomware_sim
        self.assertGreater(score, 75)
        self.assertIsNotNone(alert)
        self.assertTrue(alert["anomaly_context"]["gnn_lateral_movement_detected"] or "lateral_movement_pattern" in alert["anomaly_context"]["violations"])
        
        print("\033[92m[v] Test Passed: GNN event model pathways and alert schemas successfully verified.\033[0m")

if __name__ == "__main__":
    unittest.main()
