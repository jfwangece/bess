#ifndef BESS_MODULES_DYSSECTWORKINGCORE_H_
#define BESS_MODULES_DYSSECTWORKINGCORE_H_

#include "../port.h"
#include "../module.h"
#include "../kmod/llring.h"
#include "../utils/format.h"
#include "../pb/module_msg.pb.h"

#include "dyssectnf.h"
#include "../utils/ip.h"
#include "../utils/tcp.h"
#include "../utils/ether.h"
#include "../drivers/pmd.h"
#include "../utils/endian.h"
#include "../utils/cuckoo_map.h"

#include "dyssectworking.h"
#include "dyssectoffloadingcore.h"
#include "controller.h"
               
using bess::utils::Tcp;
using bess::utils::Ipv4;
using bess::utils::Ethernet;

class DyssectWorkingCore final : public DyssectWorking {
        public:
                static const gate_idx_t kNumIGates = 0;
                static const gate_idx_t kNumOGates = 1;

                DyssectWorkingCore() : DyssectWorking() { }

                DyssectState* ExtractState(bess::Packet *);
                CommandResponse Init(const bess::pb::DyssectWorkingCoreArg&);
                struct task_result RunTask(Context*, bess::PacketBatch*, void*) override;
	
	private:
		uint32_t qsize;
		llring *mypackets;

		void TransferR(Context *, bess::PacketBatch *);
		void TransferShard(Context *, bess::PacketBatch *);
		void TransferOffloading(Context *, bess::PacketBatch *); 

		void run(Context *, bess::PacketBatch *, llring *);
		uint32_t process(Context *ctx, bess::PacketBatch *batch, llring *q);
};

#endif // BESS_MODULES_DYSSECTWORKINGCORE_H_
