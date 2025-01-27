// Copyright (c) 2014-2016, The Regents of the University of California.
// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef BESS_DRIVERS_PMD_H_
#define BESS_DRIVERS_PMD_H_

#include <shared_mutex>
#include <string>

#include <rte_config.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include "../module.h"
#include "../port.h"
#include "../utils/regression.h"

typedef uint16_t dpdk_port_t;

#define DPDK_PORT_UNKNOWN RTE_MAX_ETHPORTS
/*!
 * This driver binds a port to a device using DPDK.
 * This is the recommended driver for performance.
 */
class PMDPort final : public Port {
 public:
  PMDPort()
      : Port(),
        dpdk_port_id_(DPDK_PORT_UNKNOWN),
        hot_plugged_(false),
        node_placement_(UNCONSTRAINED_SOCKET) {}

  void InitDriver() override;

  /*!
   * Initialize the port. Doesn't actually bind to the device, just grabs all
   * the parameters. InitDriver() does the binding.
   *
   * PARAMETERS:
   * * bool loopback : Is this a loopback device?
   * * uint32 port_id : The DPDK port ID for the device to bind to.
   * * string pci : The PCI address of the port to bind to.
   * * string vdev : If a virtual device, the virtual device address (e.g.
   * tun/tap)
   *
   * EXPECTS:
   * * Must specify exactly one of port_id or PCI or vdev.
   */
  CommandResponse Init(const bess::pb::PMDPortArg &arg);

  /*!
   * Release the device.
   */
  void DeInit() override;

  /*!
   * Copies rte port statistics into queue_stats datastructure (see port.h).
   *
   * PARAMETERS:
   * * bool reset : if true, reset DPDK local statistics and return (do not
   * collect stats).
   */
  void CollectStats(bool reset) override;

  /*!
   * Receives packets from the device.
   *
   * PARAMETERS:
   * * queue_t quid : NIC queue to receive from.
   * * bess::Packet **pkts   : buffer to store received packets in to.
   * * int cnt  : max number of packets to pull.
   *
   * EXPECTS:
   * * Only call this after calling Init with a device.
   * * Don't call this after calling DeInit().
   *
   * RETURNS:
   * * Total number of packets received (<=cnt)
   */
  int RecvPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

  /*!
   * Sends packets out on the device.
   *
   * PARAMETERS:
   * * queue_t quid : NIC queue to transmit on.
   * * bess::Packet ** pkts   : packets to transmit.
   * * int cnt  : number of packets in pkts to transmit.
   *
   * EXPECTS:
   * * Only call this after calling Init with a device.
   * * Don't call this after calling DeInit().
   *
   * RETURNS:
   * * Total number of packets sent (<=cnt).
   */
  int SendPackets(queue_t qid, bess::Packet **pkts, int cnt) override;

  void TurnOnOffIntr(queue_t qid, bool on);

  void SleepUntilRxInterrupt();
  void SyncClock();
  void TestClock();

  uint64_t GetFlags() const override {
    return DRIVER_FLAG_SELF_INC_STATS | DRIVER_FLAG_SELF_OUT_STATS;
  }

  LinkStatus GetLinkStatus() override;

  CommandResponse UpdateConf(const Conf &conf) override;

  /*!
   * Get any placement constraints that need to be met when receiving from this
   * port.
   */
  placement_constraint GetNodePlacementConstraint() const override {
    return node_placement_;
  }

  dpdk_port_t get_dpdk_port_id() {
    return dpdk_port_id_;
  }

  /*
   * Converts NIC ticks to CPU cylces.
   * This function is called on every packet received and is supposed to be
   * light weight. We are taking a lock in this function which may block and
   * adds extra cpu cycles per packet. This can be optimized.
   */
  uint64_t NICCycleToCPUCycle(u_int64_t nic_cycle) {
    linear_re_lock_.lock_shared();
    uint64_t val = linear_re_.GetY(nic_cycle);
    linear_re_lock_.unlock_shared();
    return  val;
  }

  void UpdateRssReta();
  void UpdateRssReta(std::map<uint16_t, uint16_t>& moves);
  void UpdateRssReta(std::map<uint16_t, uint16_t>& moves, uint16_t total_shards);

  void UpdateRssFlow();
  void UpdateRssFlow(std::map<uint16_t, uint16_t>& moves);
  void UpdateRssFlow(std::map<uint16_t, uint16_t>& shard_moves, uint16_t total_shards);

  void BenchUpdateRssReta();
  void BenchRXQueueCount();

  // Mellanox: 512;
  uint32_t reta_size_;
  // NIC's RSS indirection table;
  struct rte_eth_rss_reta_entry64 reta_conf_[8];
  // In memory copy of the reta table on NIC.
  std::vector<uint16_t> reta_table_;
  // NIC's flow table entry for applying RSS.
  // 0: a flow rule redirecting traffic to 1 or 2.
  // 1/2: a flow rule w/ RSS as the action.
  std::vector<rte_flow*> reta_flows_;
  // At this moment, the effective reta_flow* in |reta_flows_|.
  int rte_flow_id_;
  bool is_use_group_table_ = true;

 private:
  /*!
   * The DPDK port ID number (set after binding).
   */
  dpdk_port_t dpdk_port_id_;

  /*!
   * The DPDK port Ethernet configuration.
   */
  // rte_eth_conf* dpdk_port_conf_;
  uint64_t dpdk_rss_hf_;

  /*!
   * True if device did not exist when bessd started and was later patched in.
   */
  bool hot_plugged_;

  /*!
   * True if the PMD is on the interrupt mode.
   */
  bool intr_enabled_;

  /*!
   * True if the polling thread uses Linux RT thread.
   */
  bool rt_enabled_;

  /*!
   * True if the NIC tags each packet with a timestamp.
   */
  bool timestamp_enabled_;

  /*!
   * True if this PMD runs a set of RSS benchmarks when initializing it.
   */
  bool bench_rss_;

  LinearRegression<uint64_t> linear_re_;
  std::shared_mutex linear_re_lock_;
  bool system_shutdown_;

  /*!
   * The number of idle queues of this NIC / port.
   */
  int lcore_rx_idle_count_;

  /*!
   * The timestamp of the start of this idle period
   * If zero, this NIC queue has been receiving packets
   */
  uint64_t lcore_rx_idle_ts_;
  uint64_t now_;

  /*!
   * The NUMA node to which device is attached
   */
  placement_constraint node_placement_;

  std::string driver_;  // ixgbe, i40e, ...
};

#endif  // BESS_DRIVERS_PMD_H_
