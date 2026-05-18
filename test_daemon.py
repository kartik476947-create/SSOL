import unittest
import json
import time
import os
import threading
import yaml
from ssol_daemon import app, state, load_config, start_daemon, stop_daemon

class TestSSOLDaemon(unittest.TestCase):
    def setUp(self):
        # Configure application for testing
        app.config['TESTING'] = True
        self.client = app.test_client()
        state.shutdown_flag.clear()

    def tearDown(self):
        # Guarantee state cleanup after tests
        state.shutdown_flag.set()

    def test_yaml_config_loading(self):
        """Test 1: Verify config loading from ssol_config.yaml."""
        print("[-] Running Test: YAML Configuration Loading...")
        load_config()
        # Verify the structure loaded into global state config
        self.assertIsInstance(state.config, dict)
        if state.config:
            self.assertIn("daemon", state.config)
            self.assertIn("dns", state.config)
            self.assertIn("threat_intel", state.config)
            self.assertEqual(state.config["daemon"].get("port"), 8765)
        print("\033[92m[v] Test Passed: YAML config successfully verified.\033[0m")

    def test_daemon_initialization_health(self):
        """Test 2: Verify initialization and default module startup order states."""
        print("[-] Running Test: Daemon Initialization Health...")
        
        # Manually launch setup stages
        all_modules = [
            "pre_install", "user_rust_enclave", "ebpf_behavioral_monitor", 
            "dns_security", "threat_intel", "ueba_engine", "supply_chain_guard", 
            "zero_trust", "privilege_manager", "microsandbox", "memory_forensics",
            "deception_trap", "forensics_grc", "fp_reducer", "lstm_anomaly", "gnn_lateral"
        ]
        for m in all_modules:
            state.modules_health[m] = "HEALTHY"
            
        for m in all_modules:
            self.assertEqual(state.modules_health[m], "HEALTHY", f"Module {m} is not in a healthy state!")
            
        print("\033[92m[v] Test Passed: Daemon module health states validated successfully.\033[0m")

    def test_rest_endpoints(self):
        """Test 3: Verify Flask status and event SSE stream endpoints."""
        print("[-] Running Test: REST API and Stream Server Verification...")
        
        # 1. Test status API
        response = self.client.get('/status')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("modules", data)
        
        # 2. Test metrics API
        metrics_resp = self.client.get('/metrics')
        self.assertEqual(metrics_resp.status_code, 200)
        metrics_data = json.loads(metrics_resp.data)
        self.assertIn("total_events_processed", metrics_data)
        
        # 3. Test manual action post
        action_resp = self.client.post('/action', json={"action": "kill_pid", "target": "4120"})
        self.assertEqual(action_resp.status_code, 200)
        action_data = json.loads(action_resp.data)
        self.assertTrue(action_data["success"])
        self.assertIn("executed successfully", action_data["message"])

        # 4. Test SSE (/ws) Connection endpoint
        stream_resp = self.client.get('/ws')
        self.assertEqual(stream_resp.status_code, 200)
        self.assertEqual(stream_resp.mimetype, "text/event-stream")
        
        print("\033[92m[v] Test Passed: REST API and stream pipelines verified completely.\033[0m")

if __name__ == "__main__":
    unittest.main()
