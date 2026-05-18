"""
SSOL Privilege Manager (Tier 3 - Active Defense)
================================================
Manages JIT timed root escalations, audits executions, integrates with zero-trust SVIDs,
and alerts on suspicious or off-hours escalation activity.
"""

import os
import sys
import json
import time
import socket
import logging
import threading
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "privilege_mgr", "message": "%(message)s"}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ssol_privilege_mgr")

# Try to import Zero Trust enforcer
try:
    from ssol_zero_trust import ZeroTrustEnforcer
    ZERO_TRUST_AVAILABLE = True
except ImportError:
    ZERO_TRUST_AVAILABLE = False
    logger.warning("ZeroTrust enforcer module not imported directly. Deploying standalone fallback JIT mock.")

SOCKET_PATH = "/tmp/ssol_behavioral.sock"
TCP_PORT = 9099

class PrivilegeManager:
    def __init__(self, config_path="ssol_config.yaml"):
        self.config = {}
        self.load_config(config_path)
        self.sudo_duration = self.config.get("sudo_duration_seconds", 60)
        self.failed_attempts = {} # username -> count
        self.authorized_escalations = {} # session_id -> details
        self.audit_log = []
        self.lock = threading.Lock()

        if ZERO_TRUST_AVAILABLE:
            self.zt_enforcer = ZeroTrustEnforcer(config_path)
        else:
            self.zt_enforcer = None

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.config = yaml.safe_load(f).get("ssol", {}).get("privilege", {})
            except Exception:
                self.config = {}

    def emit_telemetry(self, alert_payload):
        """Sends alerts back into the telemetry socket pipeline."""
        try:
            if hasattr(socket, "AF_UNIX") and os.name != 'nt':
                try:
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(SOCKET_PATH)
                    client.sendall(json.dumps(alert_payload).encode("utf-8") + b"\n")
                    client.close()
                    return
                except Exception:
                    pass
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", TCP_PORT))
            client.sendall(json.dumps(alert_payload).encode("utf-8") + b"\n")
            client.close()
        except Exception as e:
            logger.debug(f"Telemetry socket connection deferred: {e}")

    def request_sudo_jit(self, user, command, process_comm, duration=None):
        """Processes request to grant timed JIT root permissions for a specific command."""
        # Align with tests that pass duration as parameter keyword
        duration = duration if duration is not None else self.sudo_duration
        timestamp = time.time()
        
        # 1. Anomaly Check: suspicious process context
        if process_comm in ["nc", "curl", "python", "python3", "ransomware_sim"]:
            msg = f"Privilege escalation requested by suspicious process: '{process_comm}'!"
            logger.error(f"!!! PRIVILEGE ALERT: {msg}")
            self.trigger_privilege_alert(user, command, "suspicious_process_escalation", process_comm)
            return None, "denied_suspicious_process"

        # 2. Anomaly Check: off-hours (10 PM to 6 AM)
        current_hour = time.localtime().tm_hour
        if current_hour >= 22 or current_hour < 6:
            msg = f"Privilege escalation requested outside business hours: {current_hour}:00!"
            logger.warning(f"!!! PRIVILEGE ALERT: {msg}")
            self.trigger_privilege_alert(user, command, "off_hours_escalation")

        # 3. Request Token from Zero Trust Enforcer
        token = None
        session_id = f"jit-priv-{hash(user + command + str(timestamp)) % 1000000}"
        
        if self.zt_enforcer:
            token = self.zt_enforcer.request_jit_escalation(
                user_spiffe_id=f"spiffe://ssol.internal/user/{user}",
                requested_role="root_admin",
                duration=duration
            )
        else:
            # Standalone SVID base64 mock
            token = f"MOCK-SVID-JIT-TOKEN-{session_id}"

        # Register authorized timed access session
        expires_at = timestamp + duration
        session_details = {
            "session_id": session_id,
            "user": user,
            "command": command,
            "process_comm": process_comm,
            "granted_at": timestamp,
            "expires_at": expires_at,
            "token": token,
            "active": True,
            "status": "approved"
        }

        with self.lock:
            self.authorized_escalations[session_id] = session_details
            self.audit_log.append(session_details)
            
        logger.warning(f"!!! JIT ROOT ACCESS GRANTED !!! User '{user}' authorized to run '{command}' (Session: {session_id}, Duration: {duration}s)")
        
        # Start background timer to auto-revoke privileges
        threading.Thread(target=self._auto_revoke_timer, args=(session_id, duration), daemon=True).start()
        
        return session_id, "approved"

    def record_failed_attempt(self, user, command, reason="invalid_credentials"):
        """Logs failed escalation attempts, checking for brute-force patterns."""
        with self.lock:
            self.failed_attempts[user] = self.failed_attempts.get(user, 0) + 1
            attempts = self.failed_attempts[user]
            
        logger.warning(f"Failed privilege escalation attempt #{attempts} by user '{user}' for command '{command}' ({reason})")
        
        # Audit log failed entry
        self.audit_log.append({
            "user": user,
            "command": command,
            "timestamp": time.time(),
            "status": "failed",
            "reason": reason
        })

        if attempts >= 3:
            logger.error(f"!!! BRUTE FORCE SUDO ALERT: User '{user}' exceeded maximum failed privilege trials !!!")
            self.trigger_privilege_alert(user, command, "brute_force_sudo_abuse")
            # Reset counter on alert dispatch
            with self.lock:
                self.failed_attempts[user] = 0

    def _auto_revoke_timer(self, session_id, wait_seconds):
        """Waits and automatically revokes JIT session access."""
        time.sleep(wait_seconds)
        self.revoke_session(session_id)

    def revoke_session(self, session_id):
        """Revokes JIT privilege token."""
        with self.lock:
            if session_id in self.authorized_escalations:
                session = self.authorized_escalations[session_id]
                if session["active"]:
                    session["active"] = False
                    logger.warning(f"!!! JIT PRIVILEGE REVOKED !!! Root session '{session_id}' expired. Auto-revocation executed completely.")
                    
                    # Log audit revocation event
                    self.audit_log.append({
                        "session_id": session_id,
                        "user": session["user"],
                        "command": session["command"],
                        "timestamp": time.time(),
                        "status": "revoked"
                    })

    def verify_execution_privilege(self, session_id):
        """Verifies if JIT session remains valid for root execution checks."""
        with self.lock:
            if session_id in self.authorized_escalations:
                session = self.authorized_escalations[session_id]
                if session["active"] and time.time() < session["expires_at"]:
                    return True
        return False

    def trigger_privilege_alert(self, user, command, violation_type, process="bash"):
        """Compiles and submits alert dictionary to socket pipeline."""
        alert_payload = {
            "timestamp_ns": time.time_ns(),
            "event_type": "PRIVILEGE_ESCALATION_VIOLATION",
            "telemetry_source": "privilege_manager",
            "privilege_context": {
                "user": user,
                "command": command,
                "violation_type": violation_type,
                "action": "BLOCKED"
            },
            "process_context": {
                "comm": process,
                "pid": os.getpid(),
                "uid": 1000
            }
        }
        self.emit_telemetry(alert_payload)

if __name__ == "__main__":
    print("=========================================================================")
    print("SSOL PRIVILEGE MANAGER: Tier 3 timed JIT ROOT SUPERVISOR")
    print("=========================================================================\n")
    manager = PrivilegeManager()
    
    # 1. Clean JIT escalation request
    print("[*] Case 1: Standard admin request to update configuration:")
    sid, status = manager.request_sudo_jit("admin1", "apt-get update", "bash", duration=2)
    print(f"    --> Sudo Status: {status} | Session: {sid}")
    print(f"    --> Verifying privilege: {manager.verify_execution_privilege(sid)}")
    
    # Wait for auto-revoke
    time.sleep(3)
    print(f"    --> Verifying after timeout: {manager.verify_execution_privilege(sid)}")
    print()

    # 2. Suspicious process escalation -> DENIED
    print("[*] Case 2: Reverse shell shellscript attempting sudo JIT grant:")
    sid_s, status_s = manager.request_sudo_jit("attacker", "rm -rf /", "nc")
    print(f"    --> Sudo Status: {status_s} | Session: {sid_s}")
    print()

    # 3. Repeated failed sudo -> BRUTE FORCE ALERT
    print("[*] Case 3: Simulating brute-force failed sudo trials:")
    for _ in range(3):
        manager.record_failed_attempt("operator1", "systemctl restart sshd")
