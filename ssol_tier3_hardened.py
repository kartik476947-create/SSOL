import socket
import struct
from bcc import BPF
import time

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>

BPF_PERF_OUTPUT(defense_events);

struct event_t {
    u32 pid;
    u32 uid;
    u32 event_type; // 1 = Network Block, 2 = Whitelist Override, 3 = Raw Disk Block
    char comm[TASK_COMM_LEN];
    char target[256];
};

// =======================================================================
// 1. DIRECT BLOCK DEVICE PROTECTION (Anti-VFS Bypass for Self-Healing)
// =======================================================================
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags) {
    // Only care about modifications (Write/Append/Create)
    if ((flags & (O_WRONLY | O_RDWR | O_CREAT | O_APPEND)) == 0) {
        return 0; 
    }
    
    struct event_t data = {};
    bpf_probe_read_user_str(&data.target, sizeof(data.target), filename);
    
    // Check if trying to write to raw disk: /dev/sda or /dev/mapper/
    if (data.target[0] == '/' && data.target[1] == 'd' && data.target[2] == 'e' && data.target[3] == 'v' && data.target[4] == '/') {
        if ((data.target[5] == 's' && data.target[6] == 'd') || 
            (data.target[5] == 'm' && data.target[6] == 'a' && data.target[7] == 'p' && data.target[8] == 'p' && data.target[9] == 'e' && data.target[10] == 'r')) {
            
            // Instantly kill the process attempting raw disk write!
            bpf_send_signal(9);
            
            u64 pid_tgid = bpf_get_current_pid_tgid();
            data.pid = pid_tgid >> 32;
            data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            data.event_type = 3;
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            defense_events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    return 0;
}

// =======================================================================
// 2. NETWORK ANTI-DOS WHITELIST (Mathematical Protection)
// =======================================================================
int syscall__connect(struct pt_regs *ctx, int sockfd, const struct sockaddr __user *addr, int addrlen) {
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), addr);
    
    if (sa.sin_family == AF_INET) { 
        u32 ip = sa.sin_addr.s_addr;
        
        // Mathematical Whitelist for Critical Infra (e.g. DNS 8.8.8.8 -> 134744072 in network byte order)
        if (ip == 134744072) {
            // [WHITELIST OVERRIDE] Protect from ML False Positives! Do NOT send kill signal.
            struct event_t data = {};
            u64 pid_tgid = bpf_get_current_pid_tgid();
            data.pid = pid_tgid >> 32;
            data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            data.event_type = 2; // Whitelist override
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            char ip_str[] = "8.8.8.8 (Critical DNS)";
            __builtin_memcpy(&data.target, ip_str, sizeof(ip_str));
            defense_events.perf_submit(ctx, &data, sizeof(data));
        }
        // Simulated Malicious C2 IP (e.g. 1.1.1.1 -> 16843009 in network byte order)
        else if (ip == 16843009) {
            bpf_send_signal(9); // Natively block malicious IP
            
            struct event_t data = {};
            u64 pid_tgid = bpf_get_current_pid_tgid();
            data.pid = pid_tgid >> 32;
            data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            data.event_type = 1; // Network Block
            bpf_get_current_comm(&data.comm, sizeof(data.comm));
            
            char ip_str[] = "1.1.1.1 (Malicious C2)";
            __builtin_memcpy(&data.target, ip_str, sizeof(ip_str));
            defense_events.perf_submit(ctx, &data, sizeof(data));
        }
    }
    return 0;
}
"""

def print_defense_event(cpu, data, size):
    event = b["defense_events"].event(data)
    comm = event.comm.decode('utf-8', 'replace')
    target = event.target.decode('utf-8', 'replace')
    
    if event.event_type == 1:
        print(f"\033[41m\033[97m[ACTIVE DEFENSE: BLOCK]\033[0m \033[91m PID: {event.pid:5} | Comm: {comm:12} | Target: {target} (KILLED NATIVELY)\033[0m")
    elif event.event_type == 2:
        print(f"\033[42m\033[97m[ANTI-DOS: WHITELIST]  \033[0m \033[92m PID: {event.pid:5} | Comm: {comm:12} | Target: {target} (PROTECTED)\033[0m")
    elif event.event_type == 3:
        print(f"\033[43m\033[90m[ANTI-TAMPER: RAW DISK]\033[0m \033[93m PID: {event.pid:5} | Comm: {comm:12} | Target: {target} (VFS BYPASS PREVENTED)\033[0m")

print("Initializing SSOL Tier 3 Hardened Defense Modules...")
b = BPF(text=bpf_text)

# Attach Kprobes
openat_fnname = b.get_syscall_fnname("openat")
b.attach_kprobe(event=openat_fnname, fn_name="syscall__openat")

connect_fnname = b.get_syscall_fnname("connect")
b.attach_kprobe(event=connect_fnname, fn_name="syscall__connect")

b["defense_events"].open_perf_buffer(print_defense_event)

print("\n=========================================================================")
print("SSOL TIER 3 HARDENED DEFENSE IS LIVE.")
print("1. Direct Block Device Protection (Anti-VFS/fanotify bypass) is ON.")
print("2. Mathematical Whitelist (Anti-DoS Protection) is ON.")
print("=========================================================================\n")
print("Press Ctrl+C to stop.")

try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\nShutting down SSOL Hardened Agent...")
    exit()
