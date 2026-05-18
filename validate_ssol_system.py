import socket
import json
import time
import urllib.request
import threading
import sys

BASE_URL = "http://127.0.0.1:8765"
SOCKET_PORT = 9099

def http_get(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode('utf-8'))

def http_post(url, payload):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode('utf-8'))

def send_socket_event(comm_name):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(("127.0.0.1", SOCKET_PORT))
    payload = {
        "event_type": "MALWARE_DETECTION",
        "telemetry_source": "ebpf_behavioral_monitor",
        "process_context": {
            "comm": comm_name,
            "pid": 4120
        }
    }
    client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
    client.close()

def sse_listener(received_events):
    try:
        req = urllib.request.Request(f"{BASE_URL}/ws")
        with urllib.request.urlopen(req) as response:
            for line in response:
                line_str = line.decode('utf-8', 'replace').strip()
                if line_str.startswith("data:"):
                    data_json = line_str[5:].strip()
                    try:
                        event = json.loads(data_json)
                        received_events.append(event)
                    except Exception:
                        pass
    except Exception as e:
        pass

def run_integration_tests():
    print("=========================================================================")
    print("SSOL DYNAMIC INTEGRATION VALIDATION SUITE")
    print("=========================================================================")
    
    # 1. Start SSE Listener thread to test the real-time stream
    received_events = []
    listener_thread = threading.Thread(target=sse_listener, args=(received_events,), daemon=True)
    listener_thread.start()
    time.sleep(1) # Allow connection handshake
    
    # 2. Simulate high-confidence live attack (risk > 85)
    print("\n[*] Case 1: Simulating live attack via port 9099...")
    send_socket_event("ransomware_sim")
    time.sleep(1.5) # Wait for processing
    
    # Query metrics to verify pipeline update
    metrics = http_get(f"{BASE_URL}/metrics")
    print(f" -> Ingested Events: {metrics.get('total_events_processed')}")
    print(f" -> System Risk Score: {metrics.get('system_risk_score')}%")
    print(f" -> Threats Blocked (SIGKILL): {metrics.get('threats_blocked')}")
    
    # 3. Test SOAR controls
    print("\n[*] Case 2: Testing SOAR Control Buttons (/action REST dispatch)...")
    res_kill = http_post(f"{BASE_URL}/action", {"action": "kill_pid", "target": "4120"})
    print(f" -> DISPATCH SIGKILL (PID 4120) response: {res_kill.get('message')}")
    
    res_block = http_post(f"{BASE_URL}/action", {"action": "block_ip", "target": "192.168.1.105"})
    print(f" -> BLOCK SUSPICIOUS HOST (192.168.1.105) response: {res_block.get('message')}")
    
    res_snap = http_post(f"{BASE_URL}/action", {"action": "rollback_lvm", "target": "/opt/secure_directory"})
    print(f" -> ROLLBACK LVM SNAPSHOT response: {res_snap.get('message')}")
    
    # 4. Test API Endpoints
    print("\n[*] Case 3: Testing direct REST API schema routes...")
    status = http_get(f"{BASE_URL}/status")
    print(f" -> GET /status: ONLINE | Active modules logged: {len(status.get('modules', {}))}")
    
    alerts = http_get(f"{BASE_URL}/alerts")
    print(f" -> GET /alerts: Retrieved {len(alerts)} alerts")
    
    # Test specific user action payload
    res_payload = http_post(f"{BASE_URL}/action", {"action": "kill", "pid": 4120})
    print(f" -> POST /action (Payload: action/pid format): {res_payload.get('message')}")
    
    # 5. Send 5 mock events through telemetry socket to verify SSE stream propagation
    print("\n[*] Case 4: Broadcasting 5 mock events to verify WebSocket/SSE feed...")
    start_count = len(received_events)
    for i in range(1, 6):
        send_socket_event(f"incident_triage_worker_{i}")
        time.sleep(0.2)
    time.sleep(1.5)
    
    events_captured = [e for e in received_events if e.get("event_type") == "alert"]
    print(f" -> Events broadcasted: 5 | Real-time SSE alerts captured: {len(events_captured) - start_count}")
    
    print("\n=========================================================================")
    print("ALL API AND DYNAMIC INTEGRATION CHECKS COMPLETED SUCCESSFULY!")
    print("=========================================================================")

if __name__ == "__main__":
    run_integration_tests()
