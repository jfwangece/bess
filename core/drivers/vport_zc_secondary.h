
#ifndef BESS_DRIVERS_ZERO_COPY_VPORT_SECONDARY_
#define BESS_DRIVERS_ZERO_COPY_VPORT_SECONDARY_
#include <gtest/gtest.h>
#include <stdint.h>

#include "../kmod/llring.h"
#include "../message.h"
#include "../port.h"

#define SLOTS_PER_LLRING 1024

/* This watermark is to detect congestion and cache bouncing due to
 * head-eating-tail (needs at least 8 slots less then the total ring slots).
 * Not sure how to tune this... */
#define SLOTS_WATERMARK ((SLOTS_PER_LLRING >> 3) * 7) /* 87.5% */

/* Ideally share this with vport driver */

/* Disable (0) single producer/consumer mode for now.
 * This is slower, but just to be on the safe side. :) */
#define SINGLE_P 0
#define SINGLE_C 0

#define PORT_NAME_LEN 128
#define PORT_FNAME_LEN 128 + 256

#define MAX_QUEUES_PER_PORT_DIR 32

#define VPORT_DIR_PREFIX "sn_vports"

struct vport_inc_regs {
    uint64_t dropped;
} __cacheline_aligned;

struct vport_out_regs {
    uint32_t irq_enabled;
} __cacheline_aligned;

/* This is equivalent to the old bar */
struct vport_bar {
    char name[PORT_NAME_LEN];

    /* The term RX/TX could be very confusing for a virtual switch.
     * Instead, we use the "incoming/outgoing" convention:
     * - incoming: outside -> BESS
     * - outgoing: BESS -> outside */
    int num_inc_q;
    int num_out_q;

    struct vport_inc_regs *inc_regs[MAX_QUEUES_PER_PORT_DIR];
    struct llring *inc_qs[MAX_QUEUES_PER_PORT_DIR];

    struct vport_out_regs *out_regs[MAX_QUEUES_PER_PORT_DIR];
    struct llring *out_qs[MAX_QUEUES_PER_PORT_DIR];
};

class VPortSecondary final : public Port {
public:
    CommandResponse Init(const bess::pb::VPortSecondaryArg &arg);

    void DeInit() override;

    int RecvPackets(uint8_t qid, bess::Packet **pkts, int cnt);
    int SendPackets(uint8_t qid, bess::Packet **pkts, int cnt);

private:
    struct vport_bar *bar_ = {};

    int num_txq_;
    int num_rxq_;

    struct vport_inc_regs *tx_regs_[MAX_QUEUES_PER_PORT_DIR] = {};
    struct llring *tx_qs_[MAX_QUEUES_PER_PORT_DIR] = {};

    struct vport_out_regs *rx_regs_[MAX_QUEUES_PER_PORT_DIR] = {};
    struct llring *rx_qs_[MAX_QUEUES_PER_PORT_DIR] = {};

    int fd[MAX_QUEUES_PER_PORT_DIR] = {};
};

#endif // BESS_DRIVERS_ZERO_COPY_VPORT_SECONDARY_
