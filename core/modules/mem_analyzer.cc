
#include "mem_analyzer.h"

#include <iomanip>
#include <sstream>
#include <fstream>

#include "../packet_pool.h"
#include "../utils/format.h"
#include "rte_memzone.h"

const Commands MemAnalyzer::cmds = {
    {"get_summary", "EmptyArg",
     MODULE_CMD_FUNC(&MemAnalyzer::CommandGetSummary), Command::THREAD_SAFE},
};

CommandResponse MemAnalyzer::Init(const bess::pb::MemAnalyzerArg &arg) {
  hack_mode_ = false;
  if (arg.hack_mode()) {
    hack_mode_ = true;
  }

  if (hack_mode_) {
    hack_packets_.clear();

    std::ofstream file_ptr ("/tmp/memdump.txt");

    bess::Packet *packet = nullptr;
    uint64_t paddr, vaddr;
    int pkt_cnt = 0;
    while (true) {
      packet = reinterpret_cast<bess::Packet *>(rte_pktmbuf_alloc( \
        bess::PacketPool::GetDefaultPool(0)->pool()));
      if (packet) {
        paddr = (uint64_t)packet->paddr();
        vaddr = (uint64_t)packet->vaddr();
        PacketMem curr_val = {
          .paddr = paddr, .vaddr = vaddr, .ptr = (void*)packet,
        };
        hack_packets_.emplace(std::make_pair(paddr, curr_val));
        if (file_ptr.is_open()) {
          file_ptr << pkt_cnt << ", paddr: 0x" << std::hex << paddr << ", vaddr: 0x" << vaddr << std::dec << std::endl;
        }
        ++pkt_cnt;
      } else {
        break;
      }
    }

    if (file_ptr.is_open()) {
      file_ptr.close();
    }

    for (auto& it : hack_packets_) {
      if (it.second.ptr)
        bess::Packet::Free((bess::Packet*)it.second.ptr);
    }
  }

  return CommandSuccess();
}

void MemAnalyzer::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  int cnt = batch->cnt();
  uint64_t paddr;
  uint64_t vaddr;

  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  for (int i = 0; i < cnt ; ++i) {
    bess::Packet* curr = batch->pkts()[i];
    paddr = (uint64_t)curr->paddr();
    vaddr = (uint64_t)curr->vaddr();

    if (paddr_to_packets_.find(paddr) == paddr_to_packets_.end()) {
      PacketMem curr_val = {
        .paddr = paddr, .vaddr = vaddr, .ptr = (void*)curr,
      };
      paddr_to_packets_.emplace(std::make_pair(paddr, curr_val));
    } else {
      paddr_to_packets_[paddr].paddr = paddr;
      paddr_to_packets_[paddr].vaddr = vaddr;
      paddr_to_packets_[paddr].ptr = (void*)curr;
    }

    const struct rte_memzone* zone_ptr = curr->zone();
    paddr = zone_ptr->iova;
    vaddr = zone_ptr->addr_64;
    if (paddr_to_memzones_.find(paddr) == paddr_to_memzones_.end()) {
      MemzoneMem curr_val = {
        .paddr = paddr, .vaddr = vaddr, .ptr = zone_ptr,
      };
      paddr_to_memzones_.emplace(std::make_pair(paddr, curr_val));
    }
  }

  total_paddr_cnt_ = paddr_to_packets_.size();
  total_memzone_cnt_ = paddr_to_memzones_.size();

  mcs_unlock(&lock_, &mynode);

  RunNextModule(ctx, batch);
}

std::string MemAnalyzer::GetDesc() const {
  return bess::utils::Format("%zu paddr, %zu", total_paddr_cnt_, total_memzone_cnt_);
}

CommandResponse MemAnalyzer::CommandGetSummary(
    const bess::pb::EmptyArg &) {
  bess::pb::MemAnalyzeCommandGetSummaryResponse r;

  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  for (auto& it : paddr_to_packets_) {
    bess::pb::MemAnalyzeCommandGetSummaryResponse_PacketMem*
      p = r.add_packet_mems();

    std::ostringstream paddr_out;
    paddr_out << "hex: 0x" << std::hex << it.second.paddr << ", dec: " << std::dec << it.second.paddr;
    p->set_paddr(paddr_out.str());

    std::ostringstream vaddr_out;
    vaddr_out << "hex: 0x" << std::hex << it.second.vaddr << ", dec: " << std::dec << it.second.vaddr;;
    p->set_vaddr(vaddr_out.str());

    std::ostringstream ptr_out;
    ptr_out << it.second.ptr;
    p->set_ptr(ptr_out.str());
  }

  for (auto& it : paddr_to_memzones_) {
    bess::pb::MemAnalyzeCommandGetSummaryResponse_MemzoneMem*
      p = r.add_memzone_mems();

      std::ostringstream paddr_out;
      paddr_out << "hex: 0x" << std::hex << it.second.paddr << ", dec: " << std::dec << it.second.paddr;
      p->set_paddr(paddr_out.str());

      std::ostringstream vaddr_out;
      vaddr_out << "hex: 0x" << std::hex << it.second.vaddr << ", dec: " << std::dec << it.second.vaddr;;
      p->set_vaddr(vaddr_out.str());
  }

  mcs_unlock(&lock_, &mynode);

  return CommandSuccess(r);
}

ADD_MODULE(MemAnalyzer, "mem_analyzer",
    "Analyze the available packet memory section")
