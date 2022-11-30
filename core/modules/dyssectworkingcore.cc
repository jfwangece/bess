#include "nfv_ctrl_msg.h"
#include "dyssectcontroller.h"
#include "dyssectworkingcore.h"

static inline
bool is_priority(Ipv4 *ip, Tcp* )
{
	return ip->id.value() == 1;
}

CommandResponse DyssectWorkingCore::Init(const bess::pb::DyssectWorkingCoreArg &arg) 
{
	task_id_t tid;
	CommandResponse err;
	const char *port_name;
	burst_ = bess::PacketBatch::kMaxBurst;

	if(!arg.port().length())
	{
	  	return CommandFailure(EINVAL, "Field 'port' must be specified");
	}

	qid_ = arg.qid();
	port_name = arg.port().c_str();
	total_shards = arg.total_shards();

	const auto &it = PortBuilder::all_ports().find(port_name);

	if(it == PortBuilder::all_ports().end())
	{
	  	return CommandFailure(ENODEV, "Port %s not found", port_name);
	}

	id = arg.id();
	port_ = it->second;
	qsize = port_->rx_queue_size();
	tid = RegisterTask((void *)(uintptr_t)qid_);

	if(tid == INVALID_TASK_ID)
	{
	  	return CommandFailure(ENOMEM, "Context creation failed");
	}

	int ret;
	myown = false;
	const uint32_t kInitQueues = 16*1024;

	queue_offloading_ = (llring*) rte_malloc(NULL, llring_bytes_with_slots(kInitQueues), 64);

	if(queue_offloading_ == NULL)
	{
	  	return CommandFailure(ENOMEM, "Not memory enough");
	}

	ret = llring_init(queue_offloading_, kInitQueues, 1, 1);

        if(ret)
	{
                return CommandFailure(-ret);
	}

	regular_batch = (bess::PacketBatch *) rte_malloc(NULL, sizeof(bess::PacketBatch), 64);

	if(regular_batch == NULL)
	{
	  	return CommandFailure(ENOMEM, "Not memory enough");
	}

	mypackets = (llring*) rte_malloc(NULL, llring_bytes_with_slots(kInitQueues), 64);

	if(mypackets == NULL)
	{
	  	return CommandFailure(ENOMEM, "Not memory enough");
	}

	ret = llring_init(mypackets, kInitQueues, 1, 1);

	if(ret)
	{
		return CommandFailure(-ret);
	}

	return CommandSuccess();
}

inline
void DyssectWorkingCore::TransferR(Context *, bess::PacketBatch *) 
{
	if(llring_count(queue_offloading_) != 0) 
	{
		if(old_offloading)
			old_offloading->remove_queue(queue_offloading_);

		myown = true;
		llring* aux = queue_offloading_;
		queue_offloading_ = mypackets;
		mypackets = aux;

		if(old_offloading)
		{
			old_offloading->add_queue(queue_offloading_);
		}
	}

	for(uint32_t s = 0; s < total_shards; s++) 
	{
		if(Controller::shards[s].owner == this)
		{
			Controller::shards[s].r = Controller::shards[s].r_new;
		}
	}

	rte_atomic32_clear(&transfer_r);
}

inline
void DyssectWorkingCore::TransferShard(Context *, bess::PacketBatch *batch) 
{
	const int burst = ACCESS_ONCE(burst_);

	if(old_offloading)
	{
		old_offloading->remove_queue(queue_offloading_);
	}

	uint32_t count = MIN(rte_eth_rx_queue_count(((PMDPort*)port_)->get_port_id(), qid_), qsize);

	while(count > 0) 
	{
		myown = true;

		int ret = port_->RecvPackets(qid_, batch->pkts(), burst);

		if(ret == 0)
		{
			break;
		}

		llring_sp_enqueue_burst(mypackets, (void**) batch->pkts(), ret);

		count -= ret;
	}

	while(llring_count(queue_offloading_) != 0) 
	{
		myown = true;

		uint32_t cnt = llring_sc_dequeue_burst(queue_offloading_, (void**) batch->pkts(), burst);
		llring_sp_enqueue_burst(mypackets, (void**) batch->pkts(), cnt);
	}

	if(old_offloading)
	{
		old_offloading->add_queue(queue_offloading_);
	}

	if(!myown)
       	{
		for(uint32_t s = 0; s < total_shards; s++) 
		{
			if(Controller::shards[s].owner == this && Controller::shards[s].owner_new != 0) 
			{
				rte_atomic32_clear(&Controller::shards[s].pause);
				rte_atomic32_set(&Controller::shards[s].owner_new->had_changes, 1);
			}
		}
	}

	rte_atomic32_clear(&transfer_shard);
}

inline
void DyssectWorkingCore::TransferOffloading(Context *, bess::PacketBatch *batch) 
{
	const int burst = ACCESS_ONCE(burst_);

	if(old_offloading)
	{
		old_offloading->remove_queue(queue_offloading_);
	}
 
        while(llring_count(queue_offloading_) != 0) 
	{
                myown = true;

                uint32_t cnt = llring_sc_dequeue_burst(queue_offloading_, (void**) batch->pkts(), burst);

		llring_sp_enqueue_burst(mypackets, (void**) batch->pkts(), cnt);
        }

	if(new_offloading) 
	{
		new_offloading->add_queue(queue_offloading_);
		old_offloading = new_offloading;
	}

	rte_atomic32_clear(&transfer_offloading);
}

inline
DyssectState* DyssectWorkingCore::ExtractState(bess::Packet *pkt) 
{
	Ipv4 *ip = pkt->head_data<Ipv4 *>(sizeof(Ethernet));
	Tcp *tcp = pkt->head_data<Tcp*>(sizeof(Ethernet) + ip->header_length*4);
	uint8_t *payload = pkt->head_data<uint8_t*>(sizeof(Ethernet) + ip->header_length*4 + tcp->offset*4);

        uint32_t src_addr = ip->src.raw_value();
        uint32_t dst_addr = ip->dst.raw_value();
	uint16_t src_port = tcp->src_port.raw_value();
        uint16_t dst_port = tcp->dst_port.raw_value();
        DyssectFlow f = { 	.src_port = src_port, 
				.dst_port = dst_port, 
				.src_addr = src_addr, 
				.dst_addr = dst_addr, 
				.hash_value = reinterpret_cast<rte_mbuf*>(pkt)->hash.rss };

	DyssectState *state = 0;
	bool priority = is_priority(ip, tcp);
	ShardInfo *shards = Controller::shards;
	uint32_t s = (f.hash_value % total_shards);

	auto item = shards[s].table->find(f);
	if(item != shards[s].table->end()) 
	{
		state = item->second;

		if(!priority) 
		{
			uint32_t local_epoch = rte_atomic32_read(Controller::epoch);

			if(state->epoch != local_epoch) 
			{
				state->prob = 0;
				if(shards[s].old_bytes && state->epoch == local_epoch-1)
				{
					state->prob = ((double) state->bytes)/shards[s].old_bytes;
				}
				state->bytes = 0;
				state->epoch = local_epoch;
			}

			if(shards[s].use_2) 
			{
        	                rte_atomic32_inc(&shards[s].ref_count_2);
                	        shards[s].flows3_2->operator[](state->flow) = state;
        	                rte_atomic32_dec(&shards[s].ref_count_2);
                	} else 
			{
                        	rte_atomic32_inc(&shards[s].ref_count_1);
                        	shards[s].flows3->operator[](state->flow) = state;
	                        rte_atomic32_dec(&shards[s].ref_count_1);
        	        }
		}
	} else 
	{
		state = (DyssectState*) rte_zmalloc(NULL, sizeof(DyssectState), 64);
		void **global_state = (void**) rte_zmalloc(NULL, sfc_length * sizeof(void*), 64);

		state->global_state = global_state;

		shards[s].table->operator[](f) = state;
		state->prob = 0;
		state->shard = s;
		state->priority = priority;
		state->epoch = rte_atomic32_read(Controller::epoch);

		rte_memcpy(&(state->flow), &f, sizeof(DyssectFlow));
	}

	uint32_t iplen = ip->length.value();
	
	state->bytes += iplen;
	rte_atomic32_add(&shards[s].bytes, iplen);
	rte_atomic32_inc(&shards[s].packets);
	received_bytes += pkt->data_len();

	_set_attr_with_offset<Ipv4*>(L3_OFFSET, pkt, ip);
	_set_attr_with_offset<Tcp*>(L4_OFFSET, pkt, tcp);
	_set_attr_with_offset<uint8_t*>(PAYLOAD_OFFSET, pkt, payload);
	_set_attr_with_offset<void**>(DYSSECT_OFFSET, pkt, state->global_state);

	return state;
}

inline
void DyssectWorkingCore::run(Context *ctx, bess::PacketBatch *batch, llring *q) 
{
	bess::PacketBatch offloading_batch;
	offloading_batch.clear();
	regular_batch->clear();

        bess::Packet *pkt;
        int32_t cnt = batch->cnt();

        for(int32_t i = 0; i < cnt; i++) 
	{
                pkt = batch->pkts()[i];

		uint32_t s = reinterpret_cast<rte_mbuf*>(pkt)->hash.rss % total_shards;	

		if(rte_atomic32_read(&Controller::shards[s].pause) == 1) 
		{
		       if(Controller::shards[s].owner_new == this) 
		       {
				if(llring_sp_enqueue(Controller::shards[s].local_queue, pkt) != 0) 
				{
					bess::Packet::Free(pkt);
					continue;
				}
		       }
		} else 
		{
			DyssectState *state = ExtractState(pkt);
			if(state->priority)
			{
				regular_batch->add(pkt);
			} else 
			{
				if(state->cdf < Controller::shards[s].r) 
				{
					offloading_batch.add(pkt);
				} else 
				{
					regular_batch->add(pkt);
				}
			}
		}
	}

	if(offloading_batch.cnt()) 
	{
		cnt = llring_sp_enqueue_burst(q, (void **)offloading_batch.pkts(), offloading_batch.cnt());

		if(cnt < offloading_batch.cnt()) 
		{
			bess::Packet::Free(offloading_batch.pkts() + cnt, offloading_batch.cnt() - cnt);
		}
	}

	RunNextModule(ctx, regular_batch);
}

inline
uint32_t DyssectWorkingCore::process(Context *ctx, bess::PacketBatch *batch, llring *q) 
{
	const int burst = ACCESS_ONCE(burst_);
	ShardInfo *shards = Controller::shards;

	if(rte_atomic32_read(&had_changes) == 1) 
	{
		for(uint32_t s = 0; s < total_shards; s++) 
		{
			if(rte_atomic32_read(&shards[s].pause) == 0 && shards[s].owner_new == this) 
			{
				myown = true;
				while(llring_count(shards[s].local_queue) != 0) 
				{
					uint32_t cnt = llring_sc_dequeue_burst(shards[s].local_queue, (void**) batch->pkts(), burst);

					llring_sp_enqueue_burst(mypackets, (void**) batch->pkts(), cnt);
				}
			}
		}

		rte_atomic32_clear(&had_changes);
	}

	if(myown) 
	{
		return 0;
	}

	uint32_t cnt = port_->RecvPackets(qid_, batch->pkts(), burst);

	if(cnt == 0)
	{
		return 0;
	}

	batch->set_cnt(cnt);

	run(ctx, batch, q);

	return cnt;
}

struct task_result DyssectWorkingCore::RunTask(Context *ctx, bess::PacketBatch *batch, void *) 
{
	received_bytes = 0;
	const int pkt_overhead = 24;
	const int burst = ACCESS_ONCE(burst_);
	regular_batch->clear();

	if(myown) 
	{
		if(llring_empty(mypackets)) 
		{
			myown = false;

			for(uint32_t s = 0; s < total_shards; s++) 
			{
				if(rte_atomic32_read(&Controller::shards[s].pause) == 1 && Controller::shards[s].owner == this && Controller::shards[s].owner_new != 0) 
				{
					rte_atomic32_clear(&Controller::shards[s].pause);
					rte_atomic32_set(&Controller::shards[s].owner_new->had_changes, 1);
				}

				if(rte_atomic32_read(&Controller::shards[s].pause) == 0 && Controller::shards[s].owner_new == this) 
				{
					Controller::shards[s].owner_new = 0;
					Controller::shards[s].owner = this;
				}
			}

			if(rte_atomic32_read(&mark_to_disable) == 1) 
			{
				rte_atomic32_clear(&mark_to_disable);
				rte_atomic32_set(&disabled, 1);
                        
				return {.block = false, .packets = 0, .bits = 0};
			}

			return {.block = false, .packets = 0, .bits = 0};
		}

		uint32_t cnt = MIN(llring_count(mypackets), burst);

		if(cnt == 0) 
		{
			return {.block = false, .packets = 0, .bits = 0};
		}

		batch->clear();

		llring_sc_dequeue_burst(mypackets, (void **)(batch->pkts()), cnt);

		for(uint32_t i = 0; i < cnt; i++) 
		{
			ExtractState(batch->pkts()[i]);
			batch->add(batch->pkts()[i]);
		}

		RunNextModule(ctx, batch);
		
		return {.block = false, .packets = 0, .bits = 0};
	}

	if(rte_atomic32_read(&disabled) != 0) 
	{
		rte_atomic32_set(&disabled, 2);

		return {.block = false, .packets = 0, .bits = 0};
	}

	if(rte_atomic32_read(&controller_signal) == 1) 
	{
		if(rte_atomic32_read(&transfer_r) == 1) 
		{
			TransferR(ctx, batch);
		}

		if(rte_atomic32_read(&transfer_offloading) == 1) 
		{
			TransferOffloading(ctx, batch);
		}

		if(rte_atomic32_read(&transfer_shard) == 1) 
		{
			TransferShard(ctx, batch);
		} 

		rte_atomic32_clear(&controller_signal);

		if(!myown) 
		{
			if(rte_atomic32_read(&mark_to_disable) == 1) 
			{
				rte_atomic32_clear(&mark_to_disable);
				rte_atomic32_set(&disabled, 1);
                        
				return {.block = false, .packets = 0, .bits = 0};
			}
		}
	}

	uint32_t cnt = process(ctx, batch, queue_offloading_);
	
	return {.block = false, .packets = cnt, .bits = (received_bytes + cnt * pkt_overhead) * 8};
}

CommandResponse DyssectWorkingCore::CommandGetCoreTime(const bess::pb::EmptyArg &) {
	bess::pb::MetronCoreCommandGetCoreTimeResponse r;
	uint64_t sum = 0;
	if (bess::ctrl::dyssect_ctrl != nullptr) {
		sum = bess::ctrl::dyssect_ctrl->get_sum_core_time();
	}
	r.set_core_time(sum);
	return CommandSuccess(r);
}

ADD_MODULE(DyssectWorkingCore, "dyssectworkingcore", "Working Core of Dyssect")
