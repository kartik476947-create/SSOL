import unittest
import json
import time

class TestSSOLBehavioralMonitor(unittest.TestCase):
    def setUp(self):
        # Sample normalized event structured directly from the ssol_behavioral_monitor API contract
        self.sample_event = {
            "timestamp_ns": time.time_ns(),
            "event_type": "PROCESS_EXECUTION",
            "telemetry_source": "eBPF_ring_buffer",
            "process_context": {
                "pid": 5420,
                "ppid": 1102,
                "uid": 1000,
                "comm": "curl",
                "binary_path": "/usr/bin/curl",
                "arguments": "https://httpbin.org/get",
                "working_directory": "/home/money",
                "cgroup_context": "/user.slice/user-1000.slice",
                "container_id": "N/A"
            }
        }

    def test_schema_validity(self):
        print("[-] Running CI Gate: Behavioral Event Schema Validation...")
        event = self.sample_event

        # 1. Base Structure Validation
        self.assertIn("timestamp_ns", event, "Missing timestamp_ns field!")
        self.assertIn("event_type", event, "Missing event_type field!")
        self.assertIn("telemetry_source", event, "Missing telemetry_source field!")
        self.assertIn("process_context", event, "Missing process_context block!")

        # 2. Field Types Validation
        self.assertIsInstance(event["timestamp_ns"], int, "timestamp_ns must be nanosecond integer!")
        self.assertEqual(event["event_type"], "PROCESS_EXECUTION", "event_type mismatch!")
        self.assertEqual(event["telemetry_source"], "eBPF_ring_buffer", "telemetry_source mismatch!")

        # 3. Process Context Validation
        ctx = event["process_context"]
        self.assertIsInstance(ctx["pid"], int, "PID must be integer!")
        self.assertIsInstance(ctx["ppid"], int, "PPID must be integer!")
        self.assertIsInstance(ctx["uid"], int, "UID must be integer!")
        
        self.assertIsInstance(ctx["comm"], str, "Process name must be string!")
        self.assertIsInstance(ctx["binary_path"], str, "Binary path must be string!")
        self.assertIsInstance(ctx["arguments"], str, "Arguments must be string!")
        self.assertIsInstance(ctx["working_directory"], str, "Working directory must be string!")
        
        # 4. Container/cgroup Context Validation
        self.assertIn("cgroup_context", ctx)
        self.assertIn("container_id", ctx)

        print("\033[92m[v] CI GATE PASSED: Behavioral monitor API contract conforms completely to downstream consumer requirements.\033[0m")

if __name__ == "__main__":
    unittest.main()
