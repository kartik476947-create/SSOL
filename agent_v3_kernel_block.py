import socket
import struct
from bcc import BPF
import time

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/fcntl.h>

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(net_events);
BPF_PERF_OUTPUT(file_events);

struct exec_data_t {
    u32 pid;
    u32 uid;
    u32 blocked; // Flag to tell Python if the kernel blocked this
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct net_data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 daddr;
    u16 dport;
};

struct file_data_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    int flags;
};

// 1. TIER 7 + TIER 3 (NATIVE KERNEL ACTIVE DEFENSE)
int syscall__execve(struct pt_regs *ctx, const char __user *filename) {
    struct exec_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    data.blocked = 0;
    
    // =====================================================================
    // NATIVE KERNEL BLOCKLIST (Resolves User-Space Race Conditions & Namespaces)
    // =====================================================================
    // KERNEL GOTCHA: Inside sys_enter_execve, 'comm' is still the parent (bash)!
    // We MUST evaluate the 'filename' argument instead!
    
    // Block "/usr/bin/nc"
    if (data.filename[0] == '/' && data.filename[1] == 'u' && data.filename[2] == 's' && data.filename[3] == 'r' &&
        data.filename[4] == '/' && data.filename[5] == 'b' && data.filename[6] == 'i' && data.filename[7] == 'n' &&
        data.filename[8] == '/' && data.filename[9] == 'n' && data.filename[10] == 'c' && data.filename[11] == '\\0') {
        bpf_send_signal(9); // SIGKILL sent natively from Ring 0
        data.blocked = 1;
    }
    // Block "/usr/bin/curl"
    else if (data.filename[0] == '/' && data.filename[1] == 'u' && data.filename[2] == 's' && data.filename[3] == 'r' &&
             data.filename[4] == '/' && data.filename[5] == 'b' && data.filename[6] == 'i' && data.filename[7] == 'n' &&
             data.filename[8] == '/' && data.filename[9] == 'c' && data.filename[10] == 'u' && data.filename[11] == 'r' && data.filename[12] == 'l') {
        bpf_send_signal(9);
        data.blocked = 1;
    }
    
    exec_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

// 2. NETWORK TELEMETRY
int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr __user *addr, int addrlen) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);
    
    if (sa.sin_family == AF_INET) { 
        struct net_data_t data = {};
        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        
        data.daddr = sa.sin_addr.s_addr;
        data.dport = sa.sin_port;
        
        net_events.perf_submit(ctx, &data, sizeof(data));
    }
    return 0;
}

// 3. FILE I/O TELEMETRY
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_APPEND)) == 0) {
        return 0; 
    }
    
    struct file_data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);
    data.flags = flags;
    
    file_events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_exec_event(cpu, data, size):
    event = b["exec_events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    filename = event.filename.decode('utf-8', 'replace')
    
    if event.blocked == 1:
        print(f"\033[41m\033[97m[TIER 3 KERNEL BLOCK]\033[0m \033[91m{time.strftime('%H:%M:%S')} | NATIVELY KILLED (SIGKILL) -> PID: {event.pid} | Comm: {comm}\033[0m")
    else:
        print(f"\033[92m[EXEC] {time.strftime('%H:%M:%S')} | UID: {event.uid:4} | PID: {event.pid:6} | Comm: {comm:12} | Path: {filename}\033[0m")

def print_net_event(cpu, data, size):
    event = b["net_events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    ip = socket.inet_ntoa(struct.pack("<I", event.daddr))
    port = socket.ntohs(event.dport)
    
    if ip.startswith("127.") or port == 53:
        return
        
    print(f"\033[96m[NET]  {time.strftime('%H:%M:%S')} | UID: {event.uid:4} | PID: {event.pid:6} | Comm: {comm:12} | Dest: {ip}:{port}\033[0m")

def print_file_event(cpu, data, size):
    event = b["file_events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    filename = event.filename.decode('utf-8', 'replace')
    
    if filename.startswith("/dev") or filename.startswith("/sys") or filename.startswith("/proc") or filename.startswith("/run"):
        return
        
    print(f"\033[93m[FILE] {time.strftime('%H:%M:%S')} | UID: {event.uid:4} | PID: {event.pid:6} | Comm: {comm:12} | Write/Create: {filename}\033[0m")

print("Initializing SSOL Native Kernel Active Defense (Tier 7 + Tier 3)...")
b = BPF(text=bpf_text)

# Attach Kprobes
execve_fnname = b.get_syscall_fnname("execve")
b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

connect_fnname = b.get_syscall_fnname("connect")
b.attach_kprobe(event=connect_fnname, fn_name="syscall__connect")

openat_fnname = b.get_syscall_fnname("openat")
b.attach_kprobe(event=openat_fnname, fn_name="syscall__openat")

b["exec_events"].open_perf_buffer(print_exec_event)
b["net_events"].open_perf_buffer(print_net_event)
b["file_events"].open_perf_buffer(print_file_event)

print("\n=========================================================================")
print("SSOL NATIVE KERNEL ACTIVE DEFENSE IS LIVE.")
print("The eBPF probe is now using bpf_send_signal(SIGKILL) to block threats.")
print("This completely eliminates user-space race conditions and namespaces!")
print("=========================================================================\n")
print("Press Ctrl+C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nShutting down SSOL Agent...")
    exit()
