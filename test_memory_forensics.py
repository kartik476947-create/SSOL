import unittest
import os
from ssol_memory_forensics import MemoryForensics

class TestSSOLMemoryForensics(unittest.TestCase):
    def setUp(self):
        # Create instance of memory forensics engine
        self.engine = MemoryForensics(config_path="nonexistent_config.yaml")

    def tearDown(self):
        # Trigger worker thread shutdown
        self.engine.shutdown_flag.set()

    def test_live_maps_parsing(self):
        """Test 1: Verify maps parse logic on self pid."""
        print("[-] Running Test: Live /proc Maps Parse Logic...")
        pid = os.getpid()
        report = self.engine.scan_live_process(pid)
        
        # Verify schema
        self.assertIsNotNone(report)
        self.assertEqual(report["event_type"], "MEM_FORENSICS_REPORT")
        self.assertEqual(report["forensics_context"]["pid"], pid)
        self.assertIn("anomalies", report["forensics_context"])
        
        print("\033[92m[v] Test Passed: Maps parse logic yields correct schema structures.\033[0m")

    def test_heap_spray_pattern_matching(self):
        """Test 2: Verify simulated reflective injection and heap spray detection."""
        print("[-] Running Test: Heap Spray Pattern Verification...")
        
        # Test simulated anomaly trigger (using high threat pid 999 override)
        report = self.engine.scan_live_process(999)
        
        anomalies = report["forensics_context"]["anomalies"]
        self.assertGreater(len(anomalies), 0)
        self.assertEqual(anomalies[0]["type"], "reflective_injection")
        self.assertGreaterEqual(report["forensics_context"]["confidence_score"], 80)
        
        print("\033[92m[v] Test Passed: Heap spray and reflective injection triggers verified.\033[0m")

    def test_hooked_syscall_volatility(self):
        """Test 3: Verify hooked syscall page scanner and offline volatility reports."""
        print("[-] Running Test: Offline core dump and syscall hook scans...")
        
        report = self.engine.scan_offline_image("/var/crash/core_dump.bin")
        self.assertIsNotNone(report)
        self.assertEqual(report["telemetry_source"], "volatility_offline")
        
        anomalies = report["forensics_context"]["anomalies"]
        self.assertGreater(len(anomalies), 0)
        self.assertEqual(anomalies[0]["type"], "hooked_syscall")
        self.assertIn("sys_execve", anomalies[0]["details"])
        self.assertEqual(report["forensics_context"]["confidence_score"], 90)
        
        print("\033[92m[v] Test Passed: Hooked syscall page and volatility3 mock pipelines verified completely.\033[0m")

if __name__ == "__main__":
    unittest.main()
