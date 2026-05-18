import unittest
import time
from ssol_zero_trust import ZeroTrustEnforcer

class TestSSOLZeroTrust(unittest.TestCase):
    def setUp(self):
        # Create enforcer instance with standard testing properties
        self.enforcer = ZeroTrustEnforcer(config_path="nonexistent_config.yaml")

    def test_svid_generation(self):
        """Test 1: Verify SPIFFE SVID token generation and payload structure."""
        print("[-] Running Test: SPIFFE SVID Token Generation...")
        token = self.enforcer.generate_svid("spiffe://ssol.internal/user/test1", "sec_operator", expiry_seconds=300)
        self.assertIsNotNone(token)
        
        # Verify decoding and payload properties
        payload = self.enforcer.verify_svid(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["iss"], "spiffe://ssol.internal/ca")
        self.assertEqual(payload["sub"], "spiffe://ssol.internal/user/test1")
        self.assertEqual(payload["role"], "sec_operator")
        self.assertGreater(payload["exp"], time.time())
        
        print("\033[92m[v] Test Passed: SVID generation and verification validated.\033[0m")

    def test_jit_session_and_timeouts(self):
        """Test 2: Verify JIT session escalation and timeout revocations."""
        print("[-] Running Test: JIT Session Escalation & Expiration...")
        
        # Request immediate short-lived session (1 second)
        token = self.enforcer.request_jit_escalation("spiffe://ssol.internal/user/admin1", "root_admin", duration=1)
        self.assertIsNotNone(token)
        
        payload = self.enforcer.verify_svid(token)
        sid = payload["session_id"]
        
        self.assertIn(sid, self.enforcer.active_sessions)
        self.assertEqual(self.enforcer.active_sessions[sid]["role"], "root_admin")
        
        # Evaluate JIT access - should succeed initially
        allowed = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/admin1", token, "/etc/shadow")
        self.assertTrue(allowed)
        
        # Wait for timeout
        time.sleep(2)
        
        # Try again - should fail due to session timeout/expiration
        allowed_after_timeout = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/admin1", token, "/etc/shadow")
        self.assertFalse(allowed_after_timeout)
        self.assertNotIn(sid, self.enforcer.active_sessions)
        
        print("\033[92m[v] Test Passed: JIT sessions and timeouts enforce correct boundaries.\033[0m")

    def test_vfs_policy_gates(self):
        """Test 3: Verify access policy blocks unauthorized accesses to critical paths."""
        print("[-] Running Test: Sensitive Path Policy Gating...")
        
        # Accessing non-sensitive path should succeed by default
        allowed_normal = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/test1", None, "/home/money/docs")
        self.assertTrue(allowed_normal)
        
        # Accessing sensitive path without token -> BLOCKED
        allowed_sensitive_no_token = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/test1", None, "/etc/shadow")
        self.assertFalse(allowed_sensitive_no_token)
        
        # Accessing sensitive path with standard guest token -> BLOCKED (insufficient privilege)
        token_guest = self.enforcer.generate_svid("spiffe://ssol.internal/user/guest1", "guest")
        allowed_sensitive_guest = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/guest1", token_guest, "/etc/shadow")
        self.assertFalse(allowed_sensitive_guest)
        
        # Accessing with authorized admin token -> ALLOWED
        token_admin = self.enforcer.generate_svid("spiffe://ssol.internal/user/admin1", "root_admin")
        allowed_sensitive_admin = self.enforcer.evaluate_access_policy("spiffe://ssol.internal/user/admin1", token_admin, "/etc/shadow")
        self.assertTrue(allowed_sensitive_admin)
        
        print("\033[92m[v] Test Passed: Zero-trust filesystem policy gates are fully active.\033[0m")

if __name__ == "__main__":
    unittest.main()
