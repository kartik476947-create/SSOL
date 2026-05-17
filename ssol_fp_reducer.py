import time
import hashlib
import sqlite3

class SSOLFalsePositiveReducer:
    def __init__(self, trusted_signatures: set, local_sqlite_conn: sqlite3.Connection):
        self.trusted_signatures = trusted_signatures # Set of signed cryptographic hashes of admin tools
        self.db = local_sqlite_conn                  # Storage for local cluster profiles
        self.deployment_time = time.time()
        self.grace_period_seconds = 7 * 24 * 60 * 60 # 7 Days

    def generate_semantic_tree_hash(self, process_node: dict) -> str:
        # Computes hash of parent-child path lineage to represent execution signature
        lineage = []
        curr = process_node
        while curr and len(lineage) < 4:
            lineage.append(curr.get("path", ""))
            curr = curr.get("parent", None)
        lineage_str = "->".join(lineage)
        return hashlib.sha256(lineage_str.encode()).hexdigest()

    def evaluate_verdict(self, process_node: dict, raw_anomaly_score: float) -> str:
        """
        Processes alert and applies mitigation overrides during initial 7-day shadow window.
        Returns: 'BLOCK', 'QUARANTINE', 'ALERT', or 'SUPPRESS_SHADOW_LOG'
        """
        current_time = time.time()
        in_first_week = (current_time - self.deployment_time) < self.grace_period_seconds

        # Step 1: Immediate Block overrides (Absolute Policy Infractions)
        if process_node.get("violates_global_blocklist", False):
            return "BLOCK"

        # Step 2: Extract Parent-Child Semantic Cluster
        semantic_hash = self.generate_semantic_tree_hash(process_node)
        
        # Check if this parent-child cluster has been verified by the administrator
        if self.is_verified_admin_cluster(semantic_hash):
            return "SUPPRESS_SHADOW_LOG"

        # Step 3: Cryptographic Integrity Check (SBoM Trust bypass)
        binary_hash = process_node.get("hash", "")
        if binary_hash in self.trusted_signatures:
            return "SUPPRESS_SHADOW_LOG"

        # Step 4: Bayesian Score Mitigation during the first 7 days
        if in_first_week:
            is_parent_system_service = process_node.get("parent_is_systemd", False) or process_node.get("parent_is_cron", False)
            
            if is_parent_system_service and raw_anomaly_score < 0.90:
                self.record_shadow_log(process_node, raw_anomaly_score, semantic_hash)
                return "SUPPRESS_SHADOW_LOG"

        # Step 5: Escalate if score exceeds high-confidence threshold
        if raw_anomaly_score > 0.85:
            return "QUARANTINE"
        elif raw_anomaly_score >= 0.50:
            return "ALERT"
        
        return "SUPPRESS_SHADOW_LOG"

    def is_verified_admin_cluster(self, semantic_hash: str) -> bool:
        cursor = self.db.cursor()
        try:
            cursor.execute("SELECT approved FROM semantic_clusters WHERE hash = ?", (semantic_hash,))
            row = cursor.fetchone()
            return row is not None and row[0] == 1
        except sqlite3.OperationalError:
            return False

    def record_shadow_log(self, process_node, score, semantic_hash):
        cursor = self.db.cursor()
        try:
            cursor.execute('''CREATE TABLE IF NOT EXISTS semantic_clusters
                              (hash TEXT UNIQUE, comm TEXT, path TEXT, score REAL, approved INTEGER)''')
            cursor.execute(
                "INSERT OR IGNORE INTO semantic_clusters (hash, comm, path, score, approved) VALUES (?, ?, ?, ?, 0)",
                (semantic_hash, process_node.get("comm"), process_node.get("path"), score)
            )
            self.db.commit()
        except sqlite3.OperationalError:
            pass
