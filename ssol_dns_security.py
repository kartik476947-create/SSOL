"""
SSOL DNS Security Module (Tier 4 - Intelligence)
================================================
Monitors DNS queries using scapy, runs lightweight ML DGA classification,
flags DNS tunneling attacks, warns on plain UDP port 53, and emits JSON alerts.
"""

import os
import sys
import json
import time
import socket
import math
import logging
import threading
import yaml

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "dns_security", "message": "%(message)s"}',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("ssol_dns_security")

SOCKET_PATH = "/tmp/ssol_behavioral.sock"
TCP_PORT = 9099

class DGADetector:
    """Lightweight ML-style classifier for DGA domain detection."""
    def __init__(self):
        # Optimized weights to correctly separate standard low-entropy domains from random DGAs
        self.w_entropy = 1.8
        self.w_length = 0.05
        self.w_consonants = 0.5
        self.w_vowel_ratio = -2.0
        self.intercept = -4.5

    def calculate_entropy(self, domain):
        """Shannon entropy of domain string."""
        if not domain:
            return 0
        counts = {}
        for char in domain:
            counts[char] = counts.get(char, 0) + 1
        entropy = 0
        for count in counts.values():
            p = count / len(domain)
            entropy -= p * math.log2(p)
        return entropy

    def get_vowel_ratio(self, domain):
        """Ratio of vowels in domain name."""
        vowels = set("aeiou")
        domain_clean = domain.split(".")[0].lower()
        if not domain_clean:
            return 0
        v_count = sum(1 for c in domain_clean if c in vowels)
        return v_count / len(domain_clean)

    def get_consecutive_consonant_ratio(self, domain):
        """Ratio of letters that form consecutive consonants."""
        vowels = set("aeiou0123456789-.")
        domain_clean = domain.split(".")[0].lower()
        if len(domain_clean) <= 1:
            return 0
        consonants = 0
        for i in range(len(domain_clean) - 1):
            if domain_clean[i] not in vowels and domain_clean[i+1] not in vowels:
                consonants += 1
        return consonants / len(domain_clean)

    def predict_dga_score(self, domain):
        """ML inference score (Logistic Regression sigmoid approximation)."""
        domain_clean = domain.split(".")[0]
        length = len(domain_clean)
        if length < 5:
            return 0.1 # Very short domains are rarely DGA unless random

        entropy = self.calculate_entropy(domain_clean)
        vowel_ratio = self.get_vowel_ratio(domain_clean)
        consonants = self.get_consecutive_consonant_ratio(domain_clean)
        
        # Logit equation
        logit = (self.w_entropy * entropy) + \
                (self.w_length * length) + \
                (self.w_consonants * consonants) + \
                (self.w_vowel_ratio * vowel_ratio) + \
                self.intercept
                
        # Sigmoid
        score = 1 / (1 + math.exp(-max(min(logit, 15), -15)))
        return score

class DNSSecurityMonitor:
    def __init__(self, config_path="ssol_config.yaml"):
        self.config = {}
        self.load_config(config_path)
        self.dga_detector = DGADetector()
        self.shutdown_flag = threading.Event()
        
    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    self.config = yaml.safe_load(f).get("ssol", {}).get("dns", {})
            except Exception:
                self.config = {}
        self.dga_threshold = self.config.get("dga_threshold", 0.75)
        self.warn_plaintext_dns = self.config.get("warn_plaintext_dns", True)

    def emit_telemetry(self, alert_payload):
        """Sends the structured JSON alert into the central daemon socket pipeline."""
        try:
            # Try UNIX Socket first
            if hasattr(socket, "AF_UNIX") and os.name != 'nt':
                try:
                    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    client.connect(SOCKET_PATH)
                    client.sendall(json.dumps(alert_payload).encode("utf-8") + b"\n")
                    client.close()
                    return
                except Exception:
                    pass
            # Fallback to localhost TCP port 9099
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect(("127.0.0.1", TCP_PORT))
            client.sendall(json.dumps(alert_payload).encode("utf-8") + b"\n")
            client.close()
        except Exception as e:
            # Log and gracefully degrade if socket is unreachable
            logger.debug(f"Socket connection deferred: {e}")

    def inspect_query(self, domain, qtype="A"):
        """Zeek-style analysis of individual domain query."""
        domain = domain.strip().lower()
        if domain.endswith("."):
            domain = domain[:-1]

        entropy = self.dga_detector.calculate_entropy(domain)
        dga_score = self.dga_detector.predict_dga_score(domain)
        
        # 1. Tunneling Detection: abnormally long or extreme entropy
        is_tunneling = False
        classification = "benign"
        
        if len(domain) > 70 or (entropy > 4.6 and len(domain) > 40):
            is_tunneling = True
            classification = "tunnel"
        elif dga_score > self.dga_threshold:
            classification = "dga"
            
        alert_needed = is_tunneling or (classification == "dga") or self.warn_plaintext_dns
        
        event_dict = {
            "timestamp_ns": time.time_ns(),
            "event_type": "DNS_QUERY",
            "telemetry_source": "dns_monitor",
            "dns_context": {
                "domain": domain,
                "qtype": qtype,
                "entropy_score": round(entropy, 3),
                "dga_score": round(dga_score, 3),
                "classification": classification,
                "plaintext_dns_warning": self.warn_plaintext_dns
            },
            "process_context": {
                "comm": "dns_resolver",
                "pid": os.getpid(),
                "uid": os.getuid() if hasattr(os, "getuid") else 1000
            }
        }
        
        logger.info(f"Inspected DNS: {domain} | Class: {classification} | DGA Score: {dga_score:.2f}")
        
        if alert_needed:
            self.emit_telemetry(event_dict)
            
        return event_dict

    def start_packet_sniffing(self):
        """Starts background thread to capture raw socket packages if running on Linux with privileges."""
        try:
            from scapy.all import sniff, DNS, DNSQR, IP
            logger.info("Initializing Scapy raw packet sniffing on port 53...")
            
            def scapy_callback(pkt):
                if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                    dns = pkt.getlayer(DNS)
                    if dns.qd:
                        qname = dns.qd.qname.decode("utf-8", "replace")
                        qtype = dns.qd.qtype
                        # Basic mapping for qtype
                        qtype_name = "A" if qtype == 1 else "AAAA" if qtype == 28 else "TXT" if qtype == 16 else "OTHER"
                        self.inspect_query(qname, qtype_name)

            interface = self.config.get("interface", "eth0")
            
            # Start sniffing on thread
            sniff_thread = threading.Thread(
                target=lambda: sniff(filter="udp port 53", prn=scapy_callback, store=0, stop_filter=lambda x: self.shutdown_flag.is_set()),
                daemon=True
            )
            sniff_thread.start()
            logger.info(f"Scapy sniffer thread listening on {interface}")
            
        except Exception as e:
            logger.warning(f"Native scapy interface not active: {e}. Switching to graceful simulation parser mode.")

    def run_simulation(self):
        """Runs a standard sequence of diagnostic DNS queries for demo/tests."""
        test_domains = [
            ("google.com", "A"),
            ("qpw123mxnqpwo10293.org", "A"), # Simulated DGA
            ("a" * 80 + ".tunneling.malicious.com", "TXT"), # Simulated Tunneling
            ("facebook.com", "A"),
            ("x4f1b9a2c3d8e7f.xyz", "A") # Simulated DGA
        ]
        
        logger.info("Running simulated DNS telemetry scans...")
        for domain, qtype in test_domains:
            if self.shutdown_flag.is_set():
                break
            self.inspect_query(domain, qtype)
            time.sleep(0.5)

if __name__ == "__main__":
    print("=========================================================================")
    print("SSOL DNS SECURITY ENFORCER: TIER 4 ACTIVE THREAT INTEL")
    print("=========================================================================\n")
    monitor = DNSSecurityMonitor()
    monitor.start_packet_sniffing()
    try:
        monitor.run_simulation()
    except KeyboardInterrupt:
        monitor.shutdown_flag.set()
        print("\n[*] Exiting DNS Monitor.")
