import unittest
import os
import sqlite3
from ssol_threat_intel import ThreatIntelEngine

class TestSSOLThreatIntel(unittest.TestCase):
    def setUp(self):
        # Configure a test-specific SQLite database path
        self.test_db = "test_ioc_cache.db"
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass
        # Instantiate engine with test configurations
        self.engine = ThreatIntelEngine(config_path="nonexistent_config.yaml")
        # Direct override DB path for testing isolation
        self.engine.db_path = self.test_db
        self.engine.init_database()
        self.engine.seed_default_iocs()

    def tearDown(self):
        # Guarantee SQLite file cleanup
        self.engine.shutdown_flag.set()
        if hasattr(self.engine, "refresh_thread"):
            self.engine.refresh_thread.join(timeout=1.0)
        
        # Close any locks and delete test file
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_database_initialization(self):
        """Test 1: Verify local SQLite IOC database and table structure is created."""
        print("[-] Running Test: SQLite DB Schema Initialization...")
        self.assertTrue(os.path.exists(self.test_db))
        
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(iocs)")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Verify key columns exist
        self.assertIn("indicator", columns)
        self.assertIn("ttp", columns)
        self.assertIn("severity", columns)
        self.assertIn("indicator_type", columns)
        conn.close()
        print("\033[92m[v] Test Passed: Local database initialized successfully.\033[0m")

    def test_ttp_mapping(self):
        """Test 2: Verify indicator categories and TTP tagging values in seed data."""
        print("[-] Running Test: MITRE ATT&CK TTP Category Mapping...")
        
        conn = sqlite3.connect(self.test_db)
        cursor = conn.cursor()
        cursor.execute("SELECT ttp, indicator_type FROM iocs WHERE indicator = ?", ("185.112.144.11",))
        row = cursor.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "T1071.001") # Web Protocols (Command and Control)
        self.assertEqual(row[1], "ip")
        conn.close()
        print("\033[92m[v] Test Passed: TTP tags match expected classifications.\033[0m")

    def test_check_ioc_lookups(self):
        """Test 3: Verify check_ioc API correctly identifies malicious vs clean targets."""
        print("[-] Running Test: IOC Lookup Queries...")
        
        # Check malicious Cobalt Strike beacon IP
        res_mal = self.engine.check_ioc("185.112.144.11")
        self.assertTrue(res_mal["matched"])
        self.assertEqual(res_mal["ttp"], "T1071.001")
        self.assertEqual(res_mal["severity"], "CRITICAL")
        self.assertIn("Cobalt Strike", res_mal["description"])

        # Check a clean IP
        res_clean = self.engine.check_ioc("8.8.8.8")
        self.assertFalse(res_clean["matched"])
        self.assertEqual(res_clean["ttp"], "N/A")
        self.assertEqual(res_clean["severity"], "INFO")
        
        print("\033[92m[v] Test Passed: check_ioc query logic performs flawlessly.\033[0m")

if __name__ == "__main__":
    unittest.main()
