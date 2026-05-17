from bcc import BPF
import time
import os
import signal
import collections

# =========================================================================
# SSOL ARCHITECTURAL LAYOUT: TIER 7 (KERNEL) & TIER 2 (DETECTION)
# =========================================================================

# Tier 7: OS Kernel eBPF Probe (C Code)
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(events);

// Upgraded structure to capture the full binary path
struct data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256]; // Dynamic extraction of the executable path
};

int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct data_t data = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    
    // Tier 7 Telemetry: Safely copy the user-space filename argument into our kernel struct
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Tier 2: Real-Time Process Profiler & Behavioral Anomaly Engine
# Designed to consume minimal CPU/RAM to avoid the EDR resource-exhaustion DoS vulnerability.
class Tier2AnomalyEngine:
    def __init__(self, profile_limit=30):
        self.profile_limit = profile_limit
        self.process_frequency = collections.Counter()
        self.uid_mappings = collections.defaultdict(set)
        self.known_paths = set()
        self.total_scans = 0
        self.is_learning = True

    def profile_process(self, comm, filename, uid):
        self.total_scans += 1
        
        # Train profile on active host baseline
        self.process_frequency[(comm, filename)] += 1
        self.uid_mappings[uid].add((comm, filename))
        self.known_paths.add(filename)

        if self.total_scans >= self.profile_limit:
            self.is_learning = False
            return False # Finished learning
        return True # Still learning

    def calculate_anomaly_score(self, comm, filename, uid):
        if self.is_learning:
            return 0.0

        score = 0.0

        # 1. Path Novelty (High Anomaly: Binary has never been executed during training)
        if filename not in self.known_paths:
            score += 0.50

        # 2. User Context (Medium Anomaly: This user/UID has never run this command before)
        if (comm, filename) not in self.uid_mappings[uid]:
            score += 0.30

        # 3. Frequency Scarcity (Low Anomaly: Run extremely rarely on this system)
        run_count = self.process_frequency[(comm, filename)]
        if run_count == 0:
            score += 0.20
        else:
            ratio = run_count / self.total_scans
            score += max(0.0, 0.20 * (1.0 - ratio))

        return min(1.0, score)

# Tier 3: Active Defense Security Policy
BLOCKLIST = ["nmap", "nc", "netcat", "ncat", "curl", "python-blocked-test"]

# Initialize Tier 2 Profiler
# We set the profiling baseline to 35 executions. For the first 35 processes, it profiles the system.
anomaly_engine = Tier2AnomalyEngine(profile_limit=35)

def print_event(cpu, data, size):
    event = b["events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    filename = event.filename.decode('utf-8', 'replace')
    uid = event.uid
    pid = event.pid

    # 1. Update/Execute Tier 2 Profiling Engine
    if anomaly_engine.is_learning:
        still_learning = anomaly_engine.profile_process(comm, filename, uid)
        print(f"\033[96m[TIER 2 PROFILER] Learning Mode ({anomaly_engine.total_scans}/{anomaly_engine.profile_limit}) | Profiled: {filename}\033[0m")
        if not still_learning:
            print("\n\033[92m[TIER 2 ML ENGINE] Baseline Established. Transitioning to Active Monitoring Mode!\033[0m\n")
        return

    # 2. Calculate Tier 2 Anomaly Score
    anomaly_score = anomaly_engine.calculate_anomaly_score(comm, filename, uid)

    # 3. Check Tier 3 Active Defense blocklist
    is_blocked = False
    for blocked_item in BLOCKLIST:
        if blocked_item == comm or blocked_item in filename:
            is_blocked = True
            break

    # 4. Process Verdict
    if is_blocked:
        try:
            os.kill(pid, signal.SIGKILL)
            print(f"\033[91m[TIER 3 ACTIVE DEFENSE] KILLED -> PID: {pid} | Command: {comm} | Path: {filename} (Policy Violation)\033[0m")
        except ProcessLookupError:
            # WSL2 Namespace isolation / latency warnings
            print(f"\033[93m[TIER 3 ADVANCED WARNING] EVADED -> PID: {pid} | Command: {comm} | Path: {filename}\n"
                  f"  └─ Cause: Asynchronous User-Space Race Condition / WSL2 PID Namespace Mismatch.\n"
                  f"  └─ Architecture Verdict: Move Active Defense hooks to eBPF Kernel space!\033[0m")
    elif anomaly_score >= 0.50:
        # High Anomaly Alert (Behavioral Anomaly)
        print(f"\033[95m[TIER 2 ANOMALY DETECTED] Score: {anomaly_score:.2f} | UID: {uid} | PID: {pid} | Comm: {comm} | Path: {filename} (Suspicious Activity!)\033[0m")
    else:
        # Standard Normal Event
        print(f"[{time.strftime('%H:%M:%S')}] SSOL Telemetry | UID: {uid:4} | PID: {pid:6} | Command: {comm:12} | Score: {anomaly_score:.2f} | Path: {filename}")

print("Initializing SecureShield OS Layer (SSOL)...")
print("Loading Tier 7 eBPF Probes into the kernel...")

try:
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")
    
    b["events"].open_perf_buffer(print_event)
    
    print("\n=========================================================================")
    print("SSOL Agent Active & Telemetry engine is live.")
    print("Tier 2 Behavioral Anomaly Detector (Process Profiler) is initialized.")
    print("Tier 3 Active Defense Kill Engine is armed.")
    print(f"Policy Blocklist: {BLOCKLIST}")
    print("=========================================================================\n")
    print("Press Ctrl+C to stop.")
    
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nShutting down SSOL Agent...")
            exit()

except Exception as e:
    print(f"\n[ERROR] Failed to load eBPF probe: {e}")
    print("\n--- SSOL ARCHITECTURE REQUIREMENT ---")
    print("eBPF is a Linux kernel technology. To run this agent, you must execute it on a Linux system or within Windows Subsystem for Linux (WSL2).")
    print("Additionally, it requires root privileges (sudo) and the 'bcc' toolchain installed.")
