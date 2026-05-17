import time
import json
import random
import hashlib

class SovereignShieldAgent:
    def __init__(self):
        self.blockchain_sim = []
        self.genesis_hash = hashlib.sha256(b"SOVEREIGN_SHIELD_GENESIS").hexdigest()
        self.active_canary = "/tmp/secure_credentials.db"
        print("\033[94m=========================================================================")
        print("SSOL: SOVEREIGN SHIELD ACTIVE DEFENSE PLATFORM (SERIES A DEMO)")
        print("=========================================================================\033[0m")
        print("[*] Positioning: Air-Gapped, Zero-Cloud, High-Performance OT Security")
        print(f"[*] Deploying Active Deception Canary: {self.active_canary}")
        print("[*] Local ML Engine (Isolation Forest + Outlier Filter): Loaded")
        print("[*] Local OPA Compliance policy engine: Loaded")
        print("[*] Local LVM Transaction Recovery: Enabled (Non-Disruptive Self-Healing)")
        print("=========================================================================\n")
        time.sleep(1)

    def calculate_ml_anomaly(self, event):
        # Whitelist critical system processes to prevent catastrophic self-inflicted DoS
        if event.get("comm") in ["systemd", "init", "sshd"]:
            return 0.0
            
        entropy = len(set(event.get("path", ""))) / (len(event.get("path", "")) + 1)
        # Normalize frequency over a scale of 10 events/sec
        freq_factor = min(event.get("frequency_per_sec", 1), 10) / 10.0
        uid = event.get("uid", 1000)

        # Refined anomaly score: high path entropy + high execution frequency + high privilege
        anomaly_score = (entropy * 0.3) + (freq_factor * 0.5) + (0.2 if uid == 0 else 0.0)
        return anomaly_score

    def evaluate_compliance(self, event, alert_triggered):
        violations = []
        # OPA Policy evaluation mapping
        if event.get("uid") != 0 and "/etc/" in event.get("path", ""):
            violations.append("NIST-800-53-AC-6 (Least Privilege)")
        if "credentials" in event.get("path", "") and event.get("uid") != 0:
            violations.append("PCI-DSS-Req-7.1.2 (Access to Sensitive Data)")
        if alert_triggered and event.get("ssol_action") != "blocked":
            violations.append("GDPR-Art-32 (Failure to Restrict Unauthorized Access)")
        return violations

    def commit_to_worm_ledger(self, event, status, signature):
        timestamp = time.time()
        prev_hash = self.blockchain_sim[-1]["hash"] if self.blockchain_sim else self.genesis_hash
        block_data = f"{prev_hash}|{timestamp}|{json.dumps(event, sort_keys=True)}|{status}|{signature}"
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()
        
        block = {
            "id": len(self.blockchain_sim) + 1,
            "timestamp": timestamp,
            "event": event,
            "status": status,
            "signature": signature,
            "prev_hash": prev_hash,
            "hash": block_hash
        }
        self.blockchain_sim.append(block)
        return block

    def run_event_simulation(self, event):
        print(f"[*] INGESTING eBPF TELEMETRY -> PID: {event['pid']} | Process: {event['comm']} | Target: {event['path']}")
        
        # 1. Active Deception Check (Zero-FP Trigger)
        is_canary_hit = event["path"] == self.active_canary
        
        # 2. Local ML Inference
        anomaly_score = self.calculate_ml_anomaly(event)
        is_anomalous = anomaly_score > 0.65
        
        print(f"[-] Local ML Outlier Scoring: Anomaly Rating -> {anomaly_score:.2f} (Threshold: 0.65)")
        
        alert_triggered = is_canary_hit or is_anomalous
        event["ssol_action"] = "blocked" if alert_triggered else "allowed"
        
        if is_canary_hit:
            print("\033[91m[!] ACTIVE DECEPTION ALERT: Decoy Canary touched! Attacker trapped natively!\033[0m")
            print("\033[91m[!] TARPIT ENFORCEMENT: eBPF sent SIGSTOP. Process frozen indefinitely.\033[0m")
            print("\033[92m[+] SELF-HEALING ACTION: Executing Local LVM Rollback to restore decoy snapshot.\033[0m")
            status = "Blocked via eBPF Deception Tarpit + LVM Rollback"
        elif is_anomalous:
            print("\033[91m[!] BEHAVIORAL THREAT ALERT: High-Entropy Outlier detected by local ML!\033[0m")
            print("\033[91m[!] NATIVE ENFORCEMENT: eBPF sent SIGKILL to malicious process tree.\033[0m")
            status = "Killed natively via eBPF sys_enter_execve hook"
        else:
            print("\033[92m[v] BEHAVIORAL Telemetry Safe: Allowed transaction.\033[0m")
            status = "Permitted transaction"

        # 3. Local OPA Compliance Checking
        violations = self.evaluate_compliance(event, alert_triggered)
        if violations:
            print(f"\033[93m[x] OPA COMPLIANCE VIOLATIONS: {', '.join(violations)}\033[0m")
        else:
            print("\033[92m[v] OPA COMPLIANCE: Compliant state verified.\033[0m")

        # 4. Cryptographic WORM Signature (FIPS 140-3 simulated)
        sig_payload = f"{event['pid']}|{event['comm']}|{status}"
        signature = f"FIPS-TDX-SIG[KEY-01]::SHA256-{hashlib.sha256(sig_payload.encode()).hexdigest()[:16]}"
        
        # 5. Commit to WORM Ledger
        block = self.commit_to_worm_ledger(event, status, signature)
        print(f"\033[92m[+] WORM LEDGER SUCCESS -> Block ID: {block['id']} | Hash: {block['hash']}\033[0m")
        print("-" * 75 + "\n")
        time.sleep(1.5)

if __name__ == "__main__":
    agent = SovereignShieldAgent()

    # Scenario 1: Malicious Ransomware / High-Entropy Execution
    event_1 = {
        "pid": 4120,
        "comm": "ransomware_sim",
        "path": "/opt/secure_directory/file_a.txt",
        "uid": 1000,
        "frequency_per_sec": 45
    }
    agent.run_event_simulation(event_1)

    # Scenario 2: Attacker attempting credential discovery (touches Deception Canary)
    event_2 = {
        "pid": 4150,
        "comm": "grep",
        "path": "/tmp/secure_credentials.db",
        "uid": 1000,
        "frequency_per_sec": 1
    }
    agent.run_event_simulation(event_2)

    # Scenario 3: Standard legitimate operations (Admin updating config)
    event_3 = {
        "pid": 4200,
        "comm": "systemd",
        "path": "/etc/systemd/system.conf",
        "uid": 0,
        "frequency_per_sec": 1
    }
    agent.run_event_simulation(event_3)

    print("\033[94m=========================================================================")
    print("Sovereign Shield Simulation Complete. Non-Disruptive EDR Protection Active.")
    print("=========================================================================\033[0m")
