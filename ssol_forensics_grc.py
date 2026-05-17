import hashlib
import time
import json

class MerkleWORM:
    def __init__(self):
        self.chain = []
        # The cryptographic anchor for the WORM ledger
        self.last_hash = hashlib.sha256(b"SSOL_GENESIS_BLOCK_v1.0").hexdigest()

    def append(self, data):
        timestamp = time.time()
        # Cryptographically link the new log to the previous hash
        payload = f"{self.last_hash}|{timestamp}|{json.dumps(data, sort_keys=True)}"
        new_hash = hashlib.sha256(payload.encode()).hexdigest()
        
        entry = {
            "id": len(self.chain) + 1,
            "timestamp": timestamp,
            "data": data,
            "prev_hash": self.last_hash,
            "hash": new_hash
        }
        self.chain.append(entry)
        self.last_hash = new_hash
        return entry

class OPAPolicyEngine:
    def evaluate(self, event):
        violations = []
        resource_class = event.get("resource", {}).get("classification", [])
        user_context = event.get("user_context", {})
        action = event.get("ssol_action", "")

        # PCI-DSS Req 7.1.2: Restrict access to cardholder data based on role
        if "PCI_CARDHOLDER_DATA" in resource_class and user_context.get("role") != "db_admin":
            violations.append("PCI-DSS-Req-7.1.2 (Unauthorized Role)")
            
        # NIST 800-53 IA-2: MFA required for sensitive access
        if "PII" in resource_class and not user_context.get("mfa_authenticated", False):
            violations.append("NIST-800-53-IA-2 (Missing MFA)")
            
        # GDPR Art. 32: Security of processing (Block required on unauthorized access)
        unauthorized = False
        if "PCI_CARDHOLDER_DATA" in resource_class and user_context.get("role") != "db_admin":
            unauthorized = True
        if "PII" in resource_class and not user_context.get("mfa_authenticated", False):
            unauthorized = True
            
        if "PII" in resource_class and unauthorized and action != "blocked":
            violations.append("GDPR-Art-32 (Failure to Block Unauthorized PII Exfiltration)")
            
        return violations

print("=========================================================================")
print("SSOL TIER 6: GRC & FORENSICS ENGINE (LIVE DEMO)")
print("=========================================================================\n")

worm = MerkleWORM()
opa = OPAPolicyEngine()

def process_event(event_name, is_red_team, event_data):
    print(f"[*] INGESTING EVENT: {event_name}")
    
    # 1. Red Team Quarantine Check
    if is_red_team:
        print("\033[93m [!] SOAR ROUTING: Event tagged with AI Red-Team eBPF mark. Quarantining from PagerDuty.\033[0m")
    else:
        print("\033[91m [!] SOAR ROUTING: Live Threat Detected. Escalating to PagerDuty & Incident Commander!\033[0m")
        
    # 2. OPA Compliance Evaluation
    print("[-] Evaluating OPA Compliance Policies (NIST, PCI, GDPR)...")
    violations = opa.evaluate(event_data)
    if violations:
        print(f"\033[91m [x] COMPLIANCE VIOLATIONS DETECTED: {', '.join(violations)}\033[0m")
    else:
        print("\033[92m [v] COMPLIANT: No policy violations.\033[0m")
        
    # 3. WORM Ledger Commitment
    print("[-] Committing to Cryptographic Merkle-Tree WORM Ledger...")
    entry = worm.append(event_data)
    print(f"\033[92m [+] WORM COMMIT SUCCESS:\033[0m")
    print(f"     -> Block ID : {entry['id']}")
    print(f"     -> Prev Hash: {entry['prev_hash'][:24]}...")
    print(f"     -> New Hash : {entry['hash']}")
    print("\n-------------------------------------------------------------------------")
    time.sleep(1)

# Scenario 1: Malicious Insider Action (Live Threat)
event_1 = {
  "event_type": "file_access",
  "resource": {
    "path": "/var/lib/mysql/pci_data.db",
    "classification": ["PII", "PCI_CARDHOLDER_DATA"]
  },
  "user_context": {
    "uid": 1005,
    "role": "developer",
    "mfa_authenticated": False
  },
  "ssol_action": "allowed" # Simulated failure to block by lower tiers
}
process_event("Insider access to PCI database without MFA", is_red_team=False, event_data=event_1)

# Scenario 2: Autonomous Red Team Agent (Safe)
event_2 = {
  "event_type": "lateral_movement_simulation",
  "resource": {
    "path": "/etc/shadow",
    "classification": ["SYSTEM_CRITICAL"]
  },
  "user_context": {
    "uid": 9999,
    "role": "red_team_agent",
    "mfa_authenticated": True
  },
  "ssol_action": "blocked" 
}
process_event("Autonomous Caldera Agent reading /etc/shadow", is_red_team=True, event_data=event_2)

# Scenario 3: Admin Maintenance (Compliant)
event_3 = {
  "event_type": "db_maintenance",
  "resource": {
    "path": "/var/lib/mysql/pci_data.db",
    "classification": ["PII", "PCI_CARDHOLDER_DATA"]
  },
  "user_context": {
    "uid": 0,
    "role": "db_admin",
    "mfa_authenticated": True
  },
  "ssol_action": "allowed" 
}
process_event("DB Admin applying patches via JIT MFA Session", is_red_team=False, event_data=event_3)
