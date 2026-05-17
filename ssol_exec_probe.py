from bcc import BPF
import time

bpf_source = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

BPF_PERF_OUTPUT(exec_events);

struct exec_data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

int syscall__execve(struct pt_regs *ctx, const char __user *filename, const char __user *const __user *argv) {
    struct exec_data_t data = {};
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    
    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["exec_events"].event(data)
    comm_name = event.comm.decode('utf-8', 'replace').strip()
    exec_path = event.filename.decode('utf-8', 'replace').strip()
    print(f"\033[92m[EXEC EVENT]\033[0m PID: {event.pid:<6} | UID: {event.uid:<5} | Comm: {comm_name:<16} | Path: {exec_path}")

print("=========================================================================")
print("SSOL TELEMETRY MIGRATION: eBPF PROCESS MONITOR")
print("=========================================================================\n")
print("[*] Ingestion Source: sys_enter_execve (Ring 0)")
print("[*] Replacing legacy Python psutil polling system...")

b = BPF(text=bpf_source)
execve_fn = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fn, fn_name="syscall__execve")
b["exec_events"].open_perf_buffer(print_event)

print("[*] SSOL eBPF Telemetry Core is LIVE. Waiting for process executions...")
print("=========================================================================\n")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n[-] Detaching eBPF probes. Telemetry system offline.")
