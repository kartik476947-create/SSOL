import unittest
import time
from ssol_privilege_manager import PrivilegeManager

class TestSSOLPrivilegeManager(unittest.TestCase):
    def setUp(self):
        # Create test instance of privilege manager
        self.manager = PrivilegeManager(config_path="nonexistent_config.yaml")

    def test_jit_escalation_grant(self):
        """Test 1: Verify JIT sudo root escalation grants and processes."""
        print("[-] Running Test: Timed JIT Sudo Grants...")
        
        # Sudo requested by benign shell process -> APPROVED
        sid, status = self.manager.request_sudo_jit("admin", "systemctl status syslog", "bash", duration=10)
        self.assertEqual(status, "approved")
        self.assertIsNotNone(sid)
        
        # Verify it has active execution privilege
        self.assertTrue(self.manager.verify_execution_privilege(sid))
        
        # Sudo requested by suspicious netcat process -> DENIED
        sid_nc, status_nc = self.manager.request_sudo_jit("admin", "whoami", "nc", duration=10)
        self.assertEqual(status_nc, "denied_suspicious_process")
        self.assertIsNone(sid_nc)

        print("\033[92m[v] Test Passed: Timed JIT sudo grants validated successfully.\033[0m")

    def test_auto_revocation_timer(self):
        """Test 2: Verify auto-revocation timer revokes permissions after duration."""
        print("[-] Running Test: Timed privilege auto-revocation loops...")
        
        # Request extremely short timed session (1 second)
        sid, status = self.manager.request_sudo_jit("operator", "tail -n 100 /var/log/syslog", "bash", duration=1)
        self.assertEqual(status, "approved")
        self.assertTrue(self.manager.verify_execution_privilege(sid))
        
        # Wait for auto-revocation
        time.sleep(2)
        
        # Should now be revoked and inactive
        self.assertFalse(self.manager.verify_execution_privilege(sid))
        
        print("\033[92m[v] Test Passed: Auto-revocation threads successfully verified.\033[0m")

    def test_auditing_and_brute_force(self):
        """Test 3: Verify security logs and brute force failed sudo attempts."""
        print("[-] Running Test: Privilege Abuse & Brute Force Audits...")
        
        # Verify audit trailing
        self.assertEqual(len(self.manager.audit_log), 0)
        
        # Request approved command
        self.manager.request_sudo_jit("admin", "apt-get update", "bash", duration=5)
        self.assertEqual(len(self.manager.audit_log), 1)
        self.assertEqual(self.manager.audit_log[0]["status"], "approved")

        # Simulate failed trial 1
        self.manager.record_failed_attempt("hacker", "cat /etc/shadow", "incorrect_password")
        self.assertEqual(len(self.manager.audit_log), 2)
        self.assertEqual(self.manager.audit_log[1]["status"], "failed")
        self.assertEqual(self.manager.failed_attempts["hacker"], 1)

        # Simulate failed trial 2 & 3 -> Brute force threshold triggers!
        self.manager.record_failed_attempt("hacker", "cat /etc/shadow", "incorrect_password")
        self.manager.record_failed_attempt("hacker", "cat /etc/shadow", "incorrect_password")
        
        # Brute force alarm resets failed attempt counter back to 0
        self.assertEqual(self.manager.failed_attempts.get("hacker", 0), 0)

        print("\033[92m[v] Test Passed: Abuse alarms and security audit records verified.\033[0m")

if __name__ == "__main__":
    unittest.main()
