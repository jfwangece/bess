#ifndef BESS_MODULES_DYSSECTOFFLOADINGCORE_H_
#define BESS_MODULES_DYSSECTOFFLOADINGCORE_H_

#include <vector>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <unordered_set>
#include <unordered_map>

#include "../module.h"
#include "../kmod/llring.h"
#include "../utils/format.h"
#include "../pb/module_msg.pb.h"

class DyssectOffloadingCore final : public Module {
	private:
		int idx;
                int burst_;

		llring *toAddQueue;
		llring *toRemoveQueue;

	public:
		uint32_t id;
		rte_atomic32_t disabled;
		rte_atomic32_t mark_to_disable;

                static const gate_idx_t kNumIGates = 0;
                static const gate_idx_t kNumOGates = 1;
		
                DyssectOffloadingCore() : Module() { }

		uint32_t core;		
		std::vector<llring*> Q;

                CommandResponse Init(const bess::pb::DyssectOffloadingCoreArg&);
                struct task_result RunTask(Context*, bess::PacketBatch*, void*) override;
		
		llring *choose() {
			return Q[idx++ % Q.size()];
		}

		void add_queue(llring* q) {
			llring_mp_enqueue(toAddQueue, (void*) q);
		}

		void remove_queue(llring* q) {
			llring_mp_enqueue(toRemoveQueue, (void*) q);
		}
};

#endif // BESS_MODULES_DYSSECTOFFLOADINGCORE_H_
