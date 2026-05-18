import unittest
import subprocess
import time
import os
from ssol_microsandbox import MicroSandbox

class TestSSOLMicroSandbox(unittest.TestCase):
    def setUp(self):
        # Create sandboxing instance
        self.sandbox = MicroSandbox(config_path="nonexistent_config.yaml")
        self.spawned_pids = []

    def tearDown(self):
        # Guarantee cleanup of all spawned test processes
        self.sandbox.shutdown_flag.set()
        for pid in self.spawned_pids:
            try:
                if os.name == 'nt':
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    os.kill(pid, 9)
            except Exception:
                pass

    def test_sandbox_startup(self):
        """Test 1: Verify namespace sandboxing initialization and registry properties."""
        print("[-] Running Test: Sandbox Startup Registry...")
        
        # Spawn sleeper process to sandbox
        if os.name == 'nt':
            p = subprocess.Popen(["ping", "127.0.0.1", "-n", "5"], stdout=subprocess.DEVNULL)
        else:
            p = subprocess.Popen(["sleep", "5"], stdout=subprocess.DEVNULL)
        self.spawned_pids.append(p.pid)

        # Run Sandboxing
        details = self.sandbox.sandbox_process(p.pid, "benign_worker")
        self.assertIsNotNone(details)
        self.assertEqual(details["pid"], p.pid)
        self.assertEqual(details["status"], "ISOLATED")
        self.assertIn(p.pid, self.sandbox.active_sandboxes)
        
        print("\033[92m[v] Test Passed: Sandbox startup registry validated.\033[0m")

    def test_seccomp_setup(self):
        """Test 2: Verify seccomp and namespaces metadata states."""
        print("[-] Running Test: Syscall & Seccomp Filtering...")
        
        if os.name == 'nt':
            p = subprocess.Popen(["ping", "127.0.0.1", "-n", "5"], stdout=subprocess.DEVNULL)
        else:
            p = subprocess.Popen(["sleep", "5"], stdout=subprocess.DEVNULL)
        self.spawned_pids.append(p.pid)

        details = self.sandbox.sandbox_process(p.pid, "sys_worker")
        # On Windows, seccomp_active will default to false, on Linux it maps to unshare success
        self.assertIn("seccomp_active", details)
        self.assertIn("namespaces_unshared", details)
        
        print("\033[92m[v] Test Passed: Seccomp and namespace metadata checked successfully.\033[0m")

    def test_escape_sigkill_termination(self):
        """Test 3: Verify sandbox escape triggers SIGKILL active enforcement."""
        print("[-] Running Test: Sandbox Escape & SIGKILL Termination...")
        
        # Spawn malicious escaping process
        if os.name == 'nt':
            p = subprocess.Popen(["ping", "127.0.0.1", "-n", "10"], stdout=subprocess.DEVNULL)
        else:
            p = subprocess.Popen(["sleep", "10"], stdout=subprocess.DEVNULL)
        self.spawned_pids.append(p.pid)

        # Run Sandboxing on escape target command
        self.sandbox.sandbox_process(p.pid, "escape_payload.sh")
        
        # Wait for escape monitor to audit and terminate PID
        time.sleep(3)
        
        # Check process is dead on host (terminated by SIGKILL dispatcher)
        self.assertFalse(self.sandbox._check_pid_alive(p.pid))
        self.assertNotIn(p.pid, self.sandbox.active_sandboxes)
        
        print("\033[92m[v] Test Passed: Escape triggers SIGKILL enforcement completely.\033[0m")

if __name__ == "__main__":
    unittest.main()
