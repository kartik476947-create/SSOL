import unittest
from ssol_dns_security import DGADetector, DNSSecurityMonitor

class TestSSOLDNSSecurity(unittest.TestCase):
    def setUp(self):
        self.detector = DGADetector()
        self.monitor = DNSSecurityMonitor()

    def test_entropy_calculation(self):
        """Test 1: Verify entropy calculation on benign and random domains."""
        print("[-] Running Test: Domain Entropy Calculations...")
        # Benign repeating characters should have low entropy
        low_entropy = self.detector.calculate_entropy("aaaaaaa")
        self.assertEqual(low_entropy, 0.0)

        # Diverse alphabet should have high entropy
        high_entropy = self.detector.calculate_entropy("abcdefg")
        self.assertGreater(high_entropy, 2.0)

        # Standard domain check
        google_ent = self.detector.calculate_entropy("google")
        self.assertAlmostEqual(google_ent, 1.9182958340544896)
        print("\033[92m[v] Test Passed: Entropy calculations are correct.\033[0m")

    def test_dga_classification(self):
        """Test 2: Verify DGA classification logic on simulated domains."""
        print("[-] Running Test: DGA ML Classifier Sigmoid Scoring...")
        
        # Google should return a very low score
        benign_score = self.detector.predict_dga_score("google.com")
        self.assertLess(benign_score, 0.5)

        # Random high entropy DGA domain should return a high score
        dga_score = self.detector.predict_dga_score("qpw123mxnqpwo10293.org")
        self.assertGreater(dga_score, 0.7)
        
        print("\033[92m[v] Test Passed: DGA ML classifier differentiates correctly.\033[0m")

    def test_tunneling_and_schema(self):
        """Test 3: Verify DNS tunneling alerts conform to socket schema specifications."""
        print("[-] Running Test: Tunneling detection and socket schema compliance...")
        
        # Inject standard domain query
        res_benign = self.monitor.inspect_query("google.com", "A")
        self.assertEqual(res_benign["dns_context"]["classification"], "benign")

        # Inject long tunneling domain query
        long_domain = "a" * 80 + ".tunneling.malicious.com"
        res_tunnel = self.monitor.inspect_query(long_domain, "TXT")
        self.assertEqual(res_tunnel["dns_context"]["classification"], "tunnel")
        self.assertEqual(res_tunnel["event_type"], "DNS_QUERY")
        self.assertIn("entropy_score", res_tunnel["dns_context"])
        self.assertIn("dga_score", res_tunnel["dns_context"])
        
        print("\033[92m[v] Test Passed: Tunneling and socket schema matches system guidelines.\033[0m")

if __name__ == "__main__":
    unittest.main()
