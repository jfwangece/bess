
#include "mem_analyzer.h"

#include <iomanip>
#include <sstream>
#include <fstream>

#include "timestamp.h"
#include "rte_memzone.h"

#include "../packet_pool.h"
#include "../utils/format.h"

const Commands MemAnalyzer::cmds = {
    {"get_summary", "EmptyArg",
     MODULE_CMD_FUNC(&MemAnalyzer::CommandGetSummary), Command::THREAD_SAFE},
};

namespace {
inline void tag_packet(bess::Packet *pkt, size_t offset, uint64_t time) {
  Timestamp::MarkerType *marker;
  uint64_t *ts;

  const size_t kStampSize = sizeof(*marker) + sizeof(*ts);
  size_t room = pkt->data_len() - offset;

  if (room < kStampSize) {
    void *ret = pkt->append(kStampSize - room);
    if (!ret) {
      // not enough tailroom for timestamp. give up
      return;
    }
  }

  marker = pkt->head_data<Timestamp::MarkerType *>(offset);
  *marker = Timestamp::kMarker;
  ts = reinterpret_cast<uint64_t *>(marker + 1);
  *ts = time;
}

static bool get_tag(bess::Packet *pkt, size_t offset, uint64_t *time) {
  auto *marker = pkt->head_data<Timestamp::MarkerType *>(offset);

  if (*marker == Timestamp::kMarker) {
    *time = *reinterpret_cast<uint64_t *>(marker + 1);
    return true;
  }
  return false;
}
} // namespace

CommandResponse MemAnalyzer::Init(const bess::pb::MemAnalyzerArg &arg) {
  hack_mode_ = false;
  if (arg.hack_mode()) {
    hack_mode_ = true;
  }

  if (arg.offset()) {
    offset_ = arg.offset();
  } else {
    std::string start_attr = arg.attr_name() + "_start_ts";
    std::string end_attr = arg.attr_name() + "_end_ts";

    using AccessMode = bess::metadata::Attribute::AccessMode;
    start_attr_id_ = AddMetadataAttr(start_attr, sizeof(uint64_t), AccessMode::kWrite);
    end_attr_id_ = AddMetadataAttr(start_attr, sizeof(uint64_t), AccessMode::kWrite);
  }

  cycles_per_batch_ = 500;
  if (arg.cycles_per_batch()) {
    cycles_per_batch_ = arg.cycles_per_batch();
  }
  cycles_per_packet_ = 1000;
  if (arg.cycles_per_packet()) {
    cycles_per_packet_ = arg.cycles_per_packet();
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
  uint64_t start_tsc = rdtsc();
  int cnt = batch->cnt();
  size_t offset = offset_;

  // tag the start
  uint64_t start_ns = tsc_to_ns(rdtsc());
  if (!hack_mode_) {
    for (int i = 0; i < cnt; ++i) {
      if (start_attr_id_ != -1 )
        set_attr<uint64_t>(this, start_attr_id_, batch->pkts()[i], start_ns);
      else
        tag_packet(batch->pkts()[i], offset, start_ns);
    }
  } else {
    uint64_t start_time = 0;
    for (auto& it : hack_packets_) {
      bess::Packet * pkt_ptr = (bess::Packet *)it.second.ptr;
      if (!get_tag(pkt_ptr, offset, &start_time)) {
        tag_packet(pkt_ptr, offset, start_ns);
      }
    }
  }

  mcslock_node_t mynode;
  mcs_lock(&lock_, &mynode);

  uint64_t paddr;
  uint64_t vaddr;
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

  // tag the end
  uint64_t end_ns = tsc_to_ns(rdtsc());
  for (int i = 0; i < cnt; ++i) {
    if (end_attr_id_ != -1 )
      set_attr<uint64_t>(this, end_attr_id_, batch->pkts()[i], end_ns);
    else
      tag_packet(batch->pkts()[i], offset + 12, end_ns);
  }

  uint64_t cycles = cycles_per_batch_ + cycles_per_packet_ * batch->cnt();
  if (cycles) {
    uint64_t target_tsc = start_tsc + cycles;
    // burn cycles until it comsumes target cycles
    while (rdtsc() < target_tsc) {
      _mm_pause();
    }
  }

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
