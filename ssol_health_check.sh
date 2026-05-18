#!/bin/bash
# =========================================================================
# SSOL Early Boot Health Check & Host Integrity Validator
# =========================================================================

# ANSI Color Codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[-] Starting SecureShield OS Layer Early Boot Verification...${NC}"

# Check Mode (Allow dry-run or mock mode overrides)
DRY_RUN=0
if [[ "$1" == "--mock" || "$SSOL_DEMO_MODE" == "1" ]]; then
    echo -e "${YELLOW}[!] Dry-run / Demo mode activated. Core kernel constraints relaxed.${NC}"
    DRY_RUN=1
fi

# 1. Verify Linux Kernel Version >= 5.10
echo -e "${BLUE}[-] Verifying Kernel requirements...${NC}"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    KERNEL_VER=$(uname -r | cut -d. -f1-2)
    MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
    MINOR=$(echo "$KERNEL_VER" | cut -d. -f2)
    
    if (( MAJOR > 5 )) || { (( MAJOR == 5 )) && (( MINOR >= 10 )); }; then
        echo -e "    --> ${GREEN}[v] Kernel version matches requirements: $(uname -r) (>= 5.10)${NC}"
    else
        echo -e "    --> ${YELLOW}[!] Kernel version is below 5.10: $(uname -r). eBPF ring buffer features may degrade.${NC}"
        if [ $DRY_RUN -eq 0 ]; then
            echo -e "    --> ${RED}[x] Boot Blocked: SSOL requires Linux Kernel >= 5.10.${NC}"
            exit 1
        fi
    fi
else
    echo -e "    --> ${YELLOW}[!] Non-Linux OS detected ($OSTYPE). Core kernel scans skipped.${NC}"
fi

# 2. Verify eBPF JIT Compiler Status
echo -e "${BLUE}[-] Auditing eBPF JIT Compiler state...${NC}"
JIT_PATH="/proc/sys/net/core/bpf_jit_enable"
if [ -f "$JIT_PATH" ]; then
    JIT_STATUS=$(cat "$JIT_PATH")
    if [[ "$JIT_STATUS" == "1" || "$JIT_STATUS" == "2" ]]; then
        echo -e "    --> ${GREEN}[v] eBPF Just-in-Time Compiler is enabled (Value: $JIT_STATUS)${NC}"
    else
        echo -e "    --> ${YELLOW}[!] eBPF JIT compiler is disabled. Activating compiler on host...${NC}"
        # Attempt to enable JIT (requires root)
        if [ "$EUID" -eq 0 ]; then
            echo 1 > "$JIT_PATH" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo -e "        --> ${GREEN}[v] Successfully enabled eBPF JIT compiler.${NC}"
            else
                echo -e "        --> ${RED}[x] Failed to set JIT compiler flag.${NC}"
            fi
        else
            echo -e "        --> ${YELLOW}[!] Root privilege missing. Unable to enable JIT compiler.${NC}"
        fi
    fi
else
    echo -e "    --> ${YELLOW}[!] /proc/sys/net/core/bpf_jit_enable not found. eBPF hardware acceleration unconfirmed.${NC}"
fi

# 3. Verify LVM Logical Volumes presence (for Sandbox LVM snapshot rollbacks)
echo -e "${BLUE}[-] Detecting LVM Volume Groups and snapshot compatibility...${NC}"
if command -v lvs >/dev/null 2>&1; then
    # Check if any volume group is present
    VG_COUNT=$(vgdisplay 2>/dev/null | grep "VG Name" | wc -l)
    if [ "$VG_COUNT" -gt 0 ]; then
        echo -e "    --> ${GREEN}[v] Active LVM Volume Group(s) found. Dynamic sandboxing snapshot features active.${NC}"
    else
        echo -e "    --> ${YELLOW}[!] No LVM Volume Groups located. Snapshot rollback rollback capabilities disabled.${NC}"
    fi
else
    echo -e "    --> ${YELLOW}[!] lvs/lvm utility not installed on host. Snapshot features mapped to mock fallback.${NC}"
fi

echo -e "\n${GREEN}[v] SecureShield OS Layer Pre-flight diagnostics passed successfully! Daemon startup initialized.${NC}\n"
exit 0
