#include "dyssectoffloadingcore.h"

CommandResponse DyssectOffloadingCore::Init(const bess::pb::DyssectOffloadingCoreArg &arg) 
{
	task_id_t tid = RegisterTask(NULL);
	if(tid == INVALID_TASK_ID)
	{
	  	return CommandFailure(ENOMEM, "Context creation failed");
	}

	id = arg.id();
	burst_ = bess::PacketBatch::kMaxBurst;

	size_t kInitSize = 64;
	toAddQueue = (llring*) rte_zmalloc(NULL, llring_bytes_with_slots(kInitSize), 64);

	if(toAddQueue == NULL)
	{
	  	return CommandFailure(ENOMEM, "Not memory enough");
	}

	toRemoveQueue = (llring*) rte_zmalloc(NULL, llring_bytes_with_slots(kInitSize), 64);

	if(toRemoveQueue == NULL)
	{
	  	return CommandFailure(ENOMEM, "Not memory enough");
	}

	int ret = llring_init(toAddQueue, kInitSize, 0, 1);

	if(ret)
	{
		return CommandFailure(-ret);
	}
	
	ret = llring_init(toRemoveQueue, kInitSize, 0, 1);

	if(ret)
	{
		return CommandFailure(-ret);
	}

	return CommandSuccess();
}

struct task_result DyssectOffloadingCore::RunTask(Context *ctx, bess::PacketBatch *batch, void *) 
{
   	llring *q;
	while(llring_sc_dequeue(toRemoveQueue, (void**) &q) == 0) 
	{
		Q.erase(std::remove(Q.begin(), Q.end(), q), Q.end());
	}

	while(llring_sc_dequeue(toAddQueue, (void**) &q) == 0) 
	{
		Q.push_back(q);
	}	

	if(Q.empty()) 
	{
		if(rte_atomic32_read(&mark_to_disable) == 1)
		{
			rte_atomic32_set(&disabled, 1);
		}

		return {.block = false, .packets = 0, .bits = 0};
	}

	uint32_t i = 0;
	uint32_t total = 0;
	const uint32_t burst = ACCESS_ONCE(burst_);
	while(total < burst) 
	{
		q = choose();
                        
		total += llring_sc_dequeue_burst(q, (void **)(batch->pkts() + total), burst - total);
		if(i++ >= Q.size())
		{
			break;
		}
	}
	
	if(total) 
	{
		batch->set_cnt(total);

		for(uint32_t i = 0; i < total; i++) 
		{
			rte_prefetch0(batch->pkts()[i]->head_data());
		}

		RunNextModule(ctx, batch);
	} else 
	{
		if(rte_atomic32_read(&mark_to_disable) == 1) 
		{
			Q.erase(std::remove(Q.begin(), Q.end(), q), Q.end());
		}
	}

	return {.block = false, .packets = 0, .bits = 0};
}

ADD_MODULE(DyssectOffloadingCore, "dyssectoffloadingcore", "Offloading core of Dyssect")
