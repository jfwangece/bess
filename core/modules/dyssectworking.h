#ifndef BESS_MODULES_DYSSECTWORKING_H_
#define BESS_MODULES_DYSSECTWORKING_H_

#include "dyssectoffloadingcore.h"

#include "../port.h"
#include "../module.h"
#include "../kmod/llring.h"

class DyssectWorking : public Module
{
	public:
		DyssectWorking() : Module() { }

		rte_atomic32_t disabled;
		rte_atomic32_t mark_to_disable;

		/* To Dyssect */
		bool myown;
		uint32_t id;
		uint32_t core;
        	uint32_t sfc_length;
		uint32_t total_shards;
		llring *queue_offloading_;
		bess::PacketBatch *regular_batch;
        	DyssectOffloadingCore *old_offloading;
        	DyssectOffloadingCore *new_offloading;

		/* Signals */
		rte_atomic32_t had_changes;
		rte_atomic32_t transfer_r;
		rte_atomic32_t transfer_shard;
		rte_atomic32_t transfer_offloading;
		rte_atomic32_t controller_signal;

		/* To BESS */
		int burst_;
                Port *port_;
                queue_t qid_;
		uint32_t received_bytes;

		llring *get_queue() 
		{
			return queue_offloading_;
		}
};


#endif // BESS_MODULES_DYSSECTWORKING_H_
