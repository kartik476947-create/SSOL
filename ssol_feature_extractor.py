import numpy as np
import math

class SSOLFeatureExtractor:
    def __init__(self, baseline_db):
        self.baseline_db = baseline_db

    def calculate_path_entropy(self, filepath: str) -> float:
        if not filepath:
            return 0.0
        entropy = 0.0
        length = len(filepath)
        char_counts = {}
        for char in filepath:
            char_counts[char] = char_counts.get(char, 0) + 1
        for count in char_counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        high_risk_paths = ["/tmp", "/dev/shm", "/var/tmp", "/boot"]
        if any(hrp in filepath for hrp in high_risk_paths):
            entropy += 2.0
        return entropy

    def get_parent_child_entropy(self, parent: str, child: str) -> float:
        transition_prob = self.baseline_db.get((parent, child), 0.0001)
        return -math.log2(transition_prob)

    def compile_feature_vector(self, raw_ebpf_telemetry: dict) -> np.ndarray:
        sys_read_count = raw_ebpf_telemetry.get("sys_read", 1)
        sys_write_count = raw_ebpf_telemetry.get("sys_write", 0)
        sys_exec_count = raw_ebpf_telemetry.get("sys_execve", 0)
        f_sys_ratio = (sys_write_count + sys_exec_count) / max(sys_read_count, 1)

        f_mem_rw = float(raw_ebpf_telemetry.get("mprotect_write_exec_calls", 0))

        H_parent_child = self.get_parent_child_entropy(
            raw_ebpf_telemetry.get("parent_comm", "init"),
            raw_ebpf_telemetry.get("comm", "unknown")
        )

        E_path = self.calculate_path_entropy(raw_ebpf_telemetry.get("path", ""))

        uid_current = raw_ebpf_telemetry.get("uid", 1000)
        uid_parent = raw_ebpf_telemetry.get("parent_uid", 1000)
        d_uid_transition = float(abs(uid_current - uid_parent))

        fd_active = raw_ebpf_telemetry.get("fd_count", 3)
        fd_mean = raw_ebpf_telemetry.get("historical_fd_mean", 3)
        r_fd = fd_active / max(fd_mean, 1)

        sigma_threads = float(raw_ebpf_telemetry.get("thread_variance", 0))
        f_socket_spawns = float(raw_ebpf_telemetry.get("connect_syscalls", 0))
        delta_libs = float(raw_ebpf_telemetry.get("unsigned_libraries_loaded", 0))

        minor_pf = raw_ebpf_telemetry.get("minor_page_faults", 0)
        major_pf = raw_ebpf_telemetry.get("major_page_faults", 1)
        r_page_faults = minor_pf / max(major_pf, 1)

        vector = np.array([
            f_sys_ratio, f_mem_rw, H_parent_child, E_path, 
            d_uid_transition, r_fd, sigma_threads, f_socket_spawns, 
            delta_libs, r_page_faults
        ], dtype=np.float32)

        return vector
