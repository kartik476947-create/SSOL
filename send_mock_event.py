import socket
import json
import sys

def send_event(comm_name="ransomware_sim"):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(("127.0.0.1", 9099))
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
        print(f"Mock event for '{comm_name}' sent successfully.")
    except Exception as e:
        print(f"Error sending mock event: {e}", file=sys.stderr)

if __name__ == "__main__":
    comm = sys.argv[1] if len(sys.argv) > 1 else "ransomware_sim"
    send_event(comm)
