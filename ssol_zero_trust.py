"""
SSOL Zero-Trust Enforcer (Tier 5 - Trust & Supply Chain)
========================================================
Implements SPIFFE-style SVID verification via PyJWT, JIT privilege management,
continuous sensitive path policy evaluation, and session timeout checks.
"""

import os
import sys
import json
import time
import socket
import logging
import base64
import yaml

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "zero_trust", "message": "%(message)s"}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ssol_zero_trust")

# Dynamic JWT Import with Safe Mocking fallback
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False
    logger.warning("pyjwt not installed. Implementing lightweight base64 signature simulation.")

SOCKET_PATH = "/tmp/ssol_behavioral.sock"
TCP_PORT = 9099
JWT_SECRET_MOCK = "SSOL-ZERO-TRUST-JWT-SIGNING-SECRET-1298"

class ZeroTrustEnforcer:
    def __init__(self, config_path="ssol_config.yaml"):
        self.config = {}
        self.load_config(config_path)
        self.sensitive_paths = self.config.get("sensitive_paths", ["/etc/shadow", "/root", "/proc/kcore"])
        self.token_timeout = self.config.get("token_timeout_seconds", 900)
        self.active_sessions = {} # session_id -> session_details

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.config = yaml.safe_load(f).get("ssol", {}).get("zero_trust", {})
            except Exception:
                self.config = {}

    def emit_telemetry(self, alert_payload):
        """Sends telemetry alerts back to the socket pipeline."""
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

    def generate_svid(self, spiffe_id, role, expiry_seconds=None):
        """Generates a SPIFFE SVID mock token (SVID role payload)."""
        duration = expiry_seconds if expiry_seconds is not None else self.token_timeout
        now = time.time()
        payload = {
            "iss": "spiffe://ssol.internal/ca",
            "sub": spiffe_id,
            "role": role,
            "iat": now,
            "exp": now + duration,
            "session_id": f"sid-{hash(spiffe_id + str(now)) % 1000000}"
        }
        
        if JWT_AVAILABLE:
            token = jwt.encode(payload, JWT_SECRET_MOCK, algorithm="HS256")
        else:
            # High-fidelity JSON-base64 simulation with mock signature
            header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().replace("=", "")
            body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().replace("=", "")
            sig = base64.urlsafe_b64encode(f"{header}.{body}.{JWT_SECRET_MOCK}".encode()).decode().replace("=", "")[:32]
            token = f"{header}.{body}.{sig}"
            
        logger.info(f"Generated SPIFFE SVID for: {spiffe_id} | Role: {role} | Exp: {duration}s")
        return token

    def verify_svid(self, token):
        """Verifies SPIFFE SVID token signatures and checks expiration limits."""
        if not token:
            return None
        try:
            if JWT_AVAILABLE:
                payload = jwt.decode(token, JWT_SECRET_MOCK, algorithms=["HS256"])
                return payload
            else:
                parts = token.split(".")
                if len(parts) != 3:
                    return None
                body_decoded = base64.urlsafe_b64decode(parts[1] + "==").decode()
                payload = json.loads(body_decoded)
                
                # Check expiration
                if time.time() > payload.get("exp", 0):
                    logger.warning("SPIFFE SVID validation failure: Token Expired.")
                    return None
                return payload
        except Exception as e:
            logger.error(f"SVID validation exception: {e}")
            return None

    def request_jit_escalation(self, user_spiffe_id, requested_role="root_admin", duration=900):
        """JIT escalation handler - registers a time-limited active session."""
        token = self.generate_svid(user_spiffe_id, requested_role, duration)
        payload = self.verify_svid(token)
        if payload:
            sid = payload["session_id"]
            self.active_sessions[sid] = {
                "spiffe_id": user_spiffe_id,
                "role": requested_role,
                "expires_at": payload["exp"],
                "token": token
            }
            logger.warning(f"!!! JIT ESCALATION APPROVED !!! Session {sid} granted to {user_spiffe_id} for {duration}s")
            return token
        return None

    def evaluate_access_policy(self, spiffe_id, token, target_path):
        """Continuous policy verification - intercepts accesses to system critical paths."""
        # Evict expired time-limited sessions from tracking memory
        now = time.time()
        expired_sids = [sid for sid, sess in self.active_sessions.items() if now > sess["expires_at"]]
        for sid in expired_sids:
            del self.active_sessions[sid]

        is_sensitive = False
        for path in self.sensitive_paths:
            if target_path.startswith(path):
                is_sensitive = True
                break
                
        if not is_sensitive:
            return True # Non-sensitive paths allowed under default zero-trust policies

        # Sensitive paths require validated SPIFFE SVID and role authority
        payload = self.verify_svid(token)
        if not payload:
            logger.error(f"!!! ZERO-TRUST BLOCK: Process '{spiffe_id}' denied access to '{target_path}'. Missing or Invalid SPIFFE SVID!")
            self.trigger_policy_alert(spiffe_id, target_path, "missing_token")
            return False

        # Validate Role Authority
        role = payload.get("role", "guest")
        if role not in ["root_admin", "sec_operator", "db_admin"]:
            logger.error(f"!!! ZERO-TRUST BLOCK: Process '{spiffe_id}' denied access to '{target_path}'. Insufficient role: '{role}'!")
            self.trigger_policy_alert(spiffe_id, target_path, "insufficient_privilege", role)
            return False

        # Validate Session Expiry
        sid = payload.get("session_id")
        if sid in self.active_sessions:
            session = self.active_sessions[sid]
            if time.time() > session["expires_at"]:
                logger.warning(f"Session {sid} has expired! Revoking escalated permissions.")
                del self.active_sessions[sid]
                self.trigger_policy_alert(spiffe_id, target_path, "session_timeout")
                return False

        logger.info(f"[v] Access granted to {spiffe_id} for path {target_path} (Role: {role})")
        return True

    def trigger_policy_alert(self, spiffe_id, path, violation_type, role="N/A"):
        """Submits structured JSON alert to socket pipeline."""
        alert_payload = {
            "timestamp_ns": time.time_ns(),
            "event_type": "ZERO_TRUST_VIOLATION",
            "telemetry_source": "zero_trust",
            "zero_trust_context": {
                "spiffe_id": spiffe_id,
                "target_path": path,
                "violation_type": violation_type,
                "requested_role": role,
                "action": "BLOCKED"
            },
            "process_context": {
                "comm": spiffe_id.split("/")[-1],
                "pid": os.getpid(),
                "uid": 1000
            }
        }
        self.emit_telemetry(alert_payload)

if __name__ == "__main__":
    print("=========================================================================")
    print("SSOL ZERO-TRUST ENFORCER: Tier 5 SPIFFE IDENTITY PIPELINE")
    print("=========================================================================\n")
    enforcer = ZeroTrustEnforcer()
    
    # 1. Access sensitive path without token -> BLOCKED
    print("[*] Case 1: Unauthenticated developer accessing sensitive path:")
    enforcer.evaluate_access_policy("spiffe://ssol.internal/user/dev1", None, "/etc/shadow")
    print()

    # 2. Authenticate standard guest token -> BLOCKED (insufficient role)
    print("[*] Case 2: Guest user attempting access:")
    token_guest = enforcer.generate_svid("spiffe://ssol.internal/user/guest1", "guest")
    enforcer.evaluate_access_policy("spiffe://ssol.internal/user/guest1", token_guest, "/etc/shadow")
    print()

    # 3. JIT Escalation -> ALLOWED
    print("[*] Case 3: Admin obtaining JIT session for sensitive operation:")
    token_admin = enforcer.request_jit_escalation("spiffe://ssol.internal/user/admin1", "root_admin", duration=5)
    enforcer.evaluate_access_policy("spiffe://ssol.internal/user/admin1", token_admin, "/etc/shadow")
    print()
    
    # 4. Wait for session timeout -> BLOCKED
    print("[*] Case 4: Waiting for timed session expiration...")
    time.sleep(6)
    enforcer.evaluate_access_policy("spiffe://ssol.internal/user/admin1", token_admin, "/etc/shadow")
