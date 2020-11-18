#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <fcntl.h>

#include "vport_zc_secondary.h"

void VPortSecondary::DeInit() {
    for (int i = 0; i < this->num_rxq_; i++) {
        if(this->fd[i] > 0) {
            close(this->fd[i]);
        }
    }
}

CommandResponse VPortSecondary::Init(
        const bess::pb::VPortSecondaryArg &arg) {
    // Initializes the number of queues.
    num_txq_ = 0;
    num_rxq_ = 0;

    char ifname[40];
    strcpy(ifname, arg.vport().c_str());
    ifname[arg.vport().size()] = '\0';
    printf("Primary VPort=%s\n", ifname);

    struct vport_bar *bar = nullptr;
    FILE* fd;
    char port_file[PORT_FNAME_LEN];

    snprintf(port_file, PORT_FNAME_LEN, "%s/%s/%s",
            P_tmpdir, VPORT_DIR_PREFIX, ifname);

    fd = fopen(port_file, "r");
    if (!fd) {
        return CommandSuccess();
    }
    int i = fread(&bar, 8, 1, fd);
    fclose(fd);
    if (i != 1) {
        return CommandSuccess();
    }
    if (!bar)
        return CommandSuccess();

    this->bar_ = bar;
    this->num_txq_ = bar->num_inc_q;
    this->num_rxq_ = bar->num_out_q;
    LOG(INFO) << bar->name;
    LOG(INFO) << "inc: " << this->num_txq_ << ", out: " << this->num_rxq_;

    for (i = 0; i < this->num_rxq_; i++) {
        this->rx_regs_[i] = bar->out_regs[i];
        this->rx_qs_[i] = bar->out_qs[i];
    }

    for (i = 0; i < this->num_txq_; i++) {
        this->tx_regs_[i] = bar->inc_regs[i];
        this->tx_qs_[i] = bar->inc_qs[i];
    }

    char fifoname[256];
    for (i = 0; i < this->num_rxq_; i++) {
        sprintf(fifoname, "%s/%s/%s.rx%d",
                P_tmpdir, VPORT_DIR_PREFIX, ifname, i);

        this->fd[i] = open(fifoname, O_RDONLY);
        assert(this->fd[i] > 0);
    }

    LOG(INFO) << "Initialized VPort[secondary]";
    return CommandSuccess();
}

int VPortSecondary::RecvPackets(uint8_t qid, bess::Packet **pkts, int cnt) {
    struct llring *q = rx_qs_[qid];

    return llring_dequeue_burst(q, (void **)pkts, cnt);
}

int VPortSecondary::SendPackets(uint8_t qid, bess::Packet **pkts, int cnt) {
    struct llring *q = tx_qs_[qid];
    /*
    // Outdated APIs
    int ret = llring_enqueue_bulk(q, (void **)pkts, cnt);
    if (ret == -LLRING_ERR_NOBUF)
        return 0;
    */

    int ret = llring_mp_enqueue_burst(q, (void **)pkts, cnt);
    if (ret == -LLRING_ERR_NOBUF) {
        return 0;
    }

    int sent = ret & (~RING_QUOT_EXCEED);
    this->tx_regs_[qid]->dropped += (cnt - sent);
    return sent;
}

ADD_DRIVER(VPortSecondary, "vportsecondary",
           "read existing zero copy virtual port for trusted user apps")
