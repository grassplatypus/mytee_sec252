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
#define SYNC_OFFSET_DEBUG_LOG       0x10

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

#endif /* _TOCTOU_COMMON_H */
