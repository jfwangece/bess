#include "dyssectcontroller.h"

static inline int from_pipe(int fd, uint8_t* addr, int len) 
{
        int n;
        int i = 0;

        while(i != len) 
	{
                n = read(fd, addr + i, len - i);
                if(n <= 0)
		{
                        return i;
		}

                i += n;
        }

        return i;
}

static inline 
int to_pipe(int fd, uint8_t* addr, int len) 
{
        int n;
        int i = 0;

        while(i != len) 
	{
                n = write(fd, addr + i, len - i);
                if(n <= 0)
		{
                        return i;
		}

                i += n;
        }

        return i;
}

static inline 
double processingtime_r(uint32_t, uint32_t) 
{
	/* TO COMPLETE FOR YOU OWN PURPOSES */

	return 1 * 1e-6;
}

static inline 
double processingtime_p(uint32_t, uint32_t) 
{
	/* TO COMPLETE FOR YOU OWN PURPOSES */

	return 1 * 1e-6;
}


const Commands DyssectController::cmds = {
        {"add_working", "AddCoreArg",
                MODULE_CMD_FUNC(&DyssectController::CommandAddDyssectWorkingCore), Command::THREAD_UNSAFE},
        {"add_offloading", "AddCoreArg",
                MODULE_CMD_FUNC(&DyssectController::CommandAddDyssectOffloadingCore), Command::THREAD_UNSAFE},
        {"start", "EmptyArg",
                MODULE_CMD_FUNC(&DyssectController::CommandStart), Command::THREAD_UNSAFE},
        {"set_slo_p", "SLOArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetSLOp), Command::THREAD_SAFE},
        {"set_slo_r", "SLOArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetSLOr), Command::THREAD_SAFE},
        {"set_ca_p", "RArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetCAp), Command::THREAD_SAFE},
        {"set_cs_p", "RArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetCSp), Command::THREAD_SAFE},
        {"set_ca_r", "RArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetCAr), Command::THREAD_SAFE},
        {"set_cs_r", "RArg",
                MODULE_CMD_FUNC(&DyssectController::CommandSetCSr), Command::THREAD_SAFE},
};

CommandResponse DyssectController::CommandSetSLOp(const bess::pb::SLOArg& arg) 
{
	SLOp = arg.slo();

	return CommandSuccess();
}

CommandResponse DyssectController::CommandSetSLOr(const bess::pb::SLOArg& arg) 
{
	SLOr = arg.slo();

	return CommandSuccess();
}

CommandResponse DyssectController::CommandSetCAp(const bess::pb::CVArg& arg) 
{
	Cap = arg.cv();

	return CommandSuccess();
}

CommandResponse DyssectController::CommandSetCSp(const bess::pb::CVArg& arg) 
{
	Csp = arg.cv();

	return CommandSuccess();
}

CommandResponse DyssectController::CommandSetCAr(const bess::pb::CVArg& arg) 
{
	Car = arg.cv();

	return CommandSuccess();
}

CommandResponse DyssectController::CommandSetCSr(const bess::pb::CVArg& arg) 
{
	Csr = arg.cv();

	return CommandSuccess();
}


CommandResponse DyssectController::Init(const bess::pb::DyssectControllerArg &arg) 
{
	const auto &it = PortBuilder::all_ports().find(arg.port().c_str());
        if(it == PortBuilder::all_ports().end())
	{
                return CommandFailure(ENODEV, "Port %s not found", arg.port().c_str());
	}

	start = false;
	port = it->second;
	sfc_length = arg.sfc_length();
	total_shards = arg.total_shards();
        port_id = ((PMDPort*)(it->second))->get_port_id();

	total_cores = arg.cores().size();
        for(auto &c : arg.cores()) 
	{
		availables.push_back(c);
	}

	last_totalpackets = 0;

        struct rte_eth_dev_info dev_info;
        int status = rte_eth_dev_info_get(port_id, &dev_info);

        if(status)
	{
                return CommandFailure(EINVAL, "Could not get device info.");
	}

        reta_size = dev_info.reta_size;
        memset(reta_conf, 0, sizeof(reta_conf));

        for(uint32_t i = 0; i < reta_size; i++)
	{
                reta_conf[i / RTE_RETA_GROUP_SIZE].mask = UINT64_MAX;
	}

	status = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);

        if(status != 0)
	{
               	return CommandFailure(EINVAL, "Could not set reta table: %s", rte_strerror(status));
	}

        task_id_t tid = RegisterTask(nullptr);

        if(tid == INVALID_TASK_ID)
	{
                return CommandFailure(ENOMEM, "Context creation failed");
	}

	next_long = 0;
	next_short = 0;

	Tr = Tp = 1 * 1e-6;
	SLOp = SLOr = 100 * 1e-9;
	Cap = Csp = Car = Csr = 1;

	solver_IN  = (char*) malloc(1024);
	solver_OUT = (char*) malloc(1024);

	memset(solver_IN, 0, 1024);
	memset(solver_OUT, 0, 1024);

	strcpy(solver_IN, arg.pipe_directory().c_str());
	strcpy(solver_OUT, arg.pipe_directory().c_str());

	strcat(solver_IN, "/solver_IN");
	strcat(solver_OUT, "/solver_OUT");
	
	status = mkfifo(solver_OUT, 0755);
        if(status < 0) 
	{
                unlink(solver_OUT);
                status = mkfifo(solver_OUT, 0755);
        }

	char buff[128];
	int __attribute__((unused)) ret = sprintf(buff, "chmod 777 %s 1>/dev/null 2>/dev/null", solver_OUT);
	ret = system(buff);

	return CommandSuccess();
}

CommandResponse DyssectController::CommandStart(const bess::pb::EmptyArg &) 
{
	Controller::epoch = (rte_atomic32_t*) rte_malloc(NULL, sizeof(rte_atomic32_t), 64);
	Controller::shards = (ShardInfo*) rte_zmalloc(NULL, total_shards * sizeof(ShardInfo), 64);

	rte_atomic32_init(Controller::epoch);

	DyssectFlow *flow_empty = (DyssectFlow*) rte_zmalloc(NULL, sizeof(DyssectFlow), 64);
	DyssectFlow *flow_deleted = (DyssectFlow*) rte_zmalloc(NULL, sizeof(DyssectFlow), 64);
        flow_empty->src_port = flow_deleted->src_port = (0);
        flow_empty->dst_port = flow_deleted->dst_port = (0);
        flow_empty->src_addr = flow_deleted->src_addr = (0);
        flow_empty->dst_addr = flow_deleted->dst_addr = (0);

	W = 1;
	E = 0;

	for(uint32_t s = 0; s < total_shards; s++) 
	{
		Controller::shards[s].table = new ((HashTable*) rte_zmalloc(NULL, sizeof(HashTable), 64)) HashTable();
		Controller::shards[s].table->set_empty_key(*flow_empty);
		Controller::shards[s].table->set_deleted_key(*flow_deleted);

		Controller::shards[s].flows3 = new ((HashTable*) rte_zmalloc(NULL, sizeof(HashTable), 64)) HashTable();
		Controller::shards[s].flows3->set_empty_key(*flow_empty);
		Controller::shards[s].flows3->set_deleted_key(*flow_deleted);
		
		Controller::shards[s].flows3_2 = new ((HashTable*) rte_zmalloc(NULL, sizeof(HashTable), 64)) HashTable();
		Controller::shards[s].flows3_2->set_empty_key(*flow_empty);
		Controller::shards[s].flows3_2->set_deleted_key(*flow_deleted);

		Controller::shards[s].use_2 = false;

		Controller::shards[s].ordered_flows = new ((std::vector<DyssectState*>*) rte_zmalloc(NULL, sizeof(std::vector<DyssectState*>), 64)) std::vector<DyssectState*>();

		rte_atomic32_init(&Controller::shards[s].pause);
		Controller::shards[s].owner = std::get<0>(working_cores[s % W]);

		rte_atomic32_init(&Controller::shards[s].bytes);
		rte_atomic32_init(&Controller::shards[s].packets);

		size_t queue_size = 2*1024;
		shards[s].local_queue = (llring*) rte_malloc(NULL, llring_bytes_with_slots(queue_size), alignof(llring));
		llring_init(shards[s].local_queue, queue_size, 1, 1);
	}

	A = (uint32_t*) rte_zmalloc(NULL, total_shards * total_cores * sizeof(uint32_t), 0);
	O = (uint32_t*) rte_zmalloc(NULL, total_cores * total_cores * sizeof(uint32_t), 0);
	newA = (uint32_t*) rte_zmalloc(NULL, total_shards * total_cores * sizeof(uint32_t), 0);
	newO = (uint32_t*) rte_zmalloc(NULL, total_cores * total_cores * sizeof(uint32_t), 0);

	for(uint32_t s = 0; s < total_shards; s++) 
	{
		for(uint32_t j = s; j < reta_size; j += total_shards)
		{
			reta_conf[j / RTE_RETA_GROUP_SIZE].reta[j % RTE_RETA_GROUP_SIZE] = s % W;
		}

		A[s*total_cores + (s % W)] = 1;
	}

	int status = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);

	if(status != 0)
	{
		return CommandFailure(EINVAL, "Could not set reta table: %s", rte_strerror(status));
	}

	for(uint32_t j = 0; j < W; j++) 
	{
		DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[j]));
		
		w->old_offloading = 0;

		rte_atomic32_clear(&w->disabled);
		rte_atomic32_clear(&w->mark_to_disable);
		
		if(E) 
		{
			DyssectOffloadingCore *e = std::get<0>(offloading_cores[j % E]);
			e->add_queue(w->get_queue());
			w->old_offloading = e;

			O[(j % E)*total_cores + j] = 1;
		}

		uint32_t c0 = availables.front();
		availables.pop_front();
		w->core = c0;

		uint32_t wid1 = std::get<2>(working_cores[j]);
		launch_worker2(wid1, c0, std::get<1>(working_cores[j]));
		resume_worker(wid1);
	}

	for(uint32_t i = 0; i < E; i++) 
	{
		DyssectOffloadingCore *e = std::get<0>(offloading_cores[i]);
		rte_atomic32_clear(&e->mark_to_disable);

		uint32_t c1 = availables.front();
		availables.pop_front();
		e->core = c1;

		uint32_t wid2 = std::get<2>(offloading_cores[i]);
		launch_worker2(wid2, c1, std::get<1>(offloading_cores[i]));
	  	resume_worker(wid2);
	}

	rte_memcpy(newA, A, total_shards * total_cores * sizeof(uint32_t));
	rte_memcpy(newO, O, total_cores  * total_cores * sizeof(uint32_t));

	start = true;

	return CommandSuccess();
}

CommandResponse DyssectController::CommandAddDyssectWorkingCore(const bess::pb::AddCoreArg &arg) 
{
        const auto &it = ModuleGraph::GetAllModules().find(arg.name());

        if(it == ModuleGraph::GetAllModules().end())
	{
                return CommandFailure(-EINVAL, "Could not add the working");
	}

	DyssectWorkingCore *working = reinterpret_cast<DyssectWorkingCore*>(it->second);
	working->sfc_length = sfc_length;

	bess::TrafficClass *tc = bess::TrafficClassBuilder::Find(arg.tc());
	detach_tc(tc);
	working_cores.push_back(std::make_tuple(working, tc, arg.wid()));

        return CommandSuccess();
}

CommandResponse DyssectController::CommandAddDyssectOffloadingCore(const bess::pb::AddCoreArg &arg) 
{
        const auto &it = ModuleGraph::GetAllModules().find(arg.name());

        if(it == ModuleGraph::GetAllModules().end())
	{
                return CommandFailure(-EINVAL, "Could not add the offloading");
	}

	DyssectOffloadingCore *offloading = reinterpret_cast<DyssectOffloadingCore*>(it->second);

	bess::TrafficClass *tc = bess::TrafficClassBuilder::Find(arg.tc());
	detach_tc(tc);
	offloading_cores.push_back(std::make_tuple(offloading, tc, arg.wid()));

        return CommandSuccess();
}

inline
void DyssectController::enable_working_cores(uint32_t from, uint32_t to) 
{
        for(uint32_t i = from; i < to; i++) 
	{
                uint32_t wid = std::get<2>(working_cores[i]);

                if(!is_worker_active(wid)) 
		{
                        if(availables.empty())
			{
                                return;
			}

                        DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));
                        rte_atomic32_clear(&w->disabled);
                        rte_atomic32_clear(&w->mark_to_disable);

                        rte_atomic32_clear(&w->transfer_shard);
                        rte_atomic32_clear(&w->transfer_offloading);
			rte_atomic32_clear(&w->controller_signal);

			w->myown = false;
			w->old_offloading = 0;

                        uint32_t core = availables.front();
                        availables.pop_front();
                        w->core = core;

                        launch_worker2(wid, core, std::get<1>(working_cores[i]));
                        resume_worker(wid);
                }
        }
}

inline
void DyssectController::enable_offloading_cores(uint32_t from, uint32_t to) 
{
        for(uint32_t i = from; i < to; i++) 
	{
                uint32_t wid = std::get<2>(offloading_cores[i]);

                if(!is_worker_active(wid)) 
		{
                        if(availables.empty()) {
                                return;
			}
                        
			DyssectOffloadingCore *e = std::get<0>(offloading_cores[i]);
                	rte_atomic32_clear(&e->disabled);
                	rte_atomic32_clear(&e->mark_to_disable);

                        uint32_t core = availables.front();
                        availables.pop_front();
                        e->core = core;

                        launch_worker2(wid, core, std::get<1>(offloading_cores[i]));
                        resume_worker(wid);
                }
        }
}

inline
void DyssectController::mark_to_disable_offloading_cores(uint32_t from, uint32_t to) 
{
        for(int32_t i = (int32_t)from-1; i >= (int32_t)to; i--) 
	{
                DyssectOffloadingCore *e = std::get<0>(offloading_cores[i]);
                rte_atomic32_set(&e->mark_to_disable, 1);
        }
}

inline
void DyssectController::mark_to_disable_working_cores(uint32_t from, uint32_t to) 
{
        for(int32_t i = (int32_t)from-1; i >= (int32_t)to; i--) 
	{
                DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));
                rte_atomic32_set(&w->mark_to_disable, 1);
        }
}

inline
void DyssectController::disable_working_cores(uint32_t from, uint32_t to) 
{
        for(int32_t i = (int32_t)from-1; i >= (int32_t)to; i--) 
	{
                DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));

                while(rte_atomic32_read(&w->disabled) != 2) 
		{
		}

                uint32_t wid = std::get<2>(working_cores[i]);
                uint32_t core = w->core;

                availables.push_back(core);
                detach_tc(std::get<1>(working_cores[i]));
                destroy_worker(wid);
        }
}

inline
void DyssectController::disable_offloading_cores(uint32_t from, uint32_t to) 
{
        for(int32_t i = (int32_t)from-1; i >= (int32_t)to; i--) 
	{
                DyssectOffloadingCore *e = std::get<0>(offloading_cores[i]);
                
		while(rte_atomic32_read(&e->disabled) != 1) 
		{
		}

                uint32_t wid = std::get<2>(offloading_cores[i]);
                uint32_t core = e->core;

                availables.push_back(core);
                detach_tc(std::get<1>(offloading_cores[i]));
                destroy_worker(wid);
        }
}

inline
void DyssectController::migration_shard(uint32_t s, uint32_t w, bool send_signal) 
{
        DyssectWorkingCore *new_working = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[w]));

        if(shards[s].owner == new_working)
	{
                return;
	}

        if(!send_signal) 
	{
                shards[s].owner_new = new_working;
                rte_atomic32_set(&shards[s].pause, 1);
        } else 
	{
                rte_atomic32_set(&shards[s].owner->transfer_shard, 1);
        }
}

inline
bool DyssectController::update_ratio() 
{
	bool changed = false;

	for(uint32_t s = 0; s < total_shards; s++) 
	{
		if(Controller::shards[s].r_new != 0.0) 
		{
                        double accum = 0.0;
                        std::vector<DyssectState*> *vec = Controller::shards[s].ordered_flows;

                        for(auto it = vec->begin(); it != vec->end(); it++) 
			{
                                accum += (*it)->prob2;
                                if(accum >= Controller::shards[s].r_new) 
				{
                                        if(accum < Controller::shards[s].r_new * SCALE)
					{
                                                Controller::shards[s].r_new = accum + EPSILON;
					}
                                        break;
                                }
                        }
                }

		if(Controller::shards[s].r != Controller::shards[s].r_new) 
		{
			DyssectWorkingCore *working = reinterpret_cast<DyssectWorkingCore*>(Controller::shards[s].owner);
			rte_atomic32_set(&working->transfer_r, 1);

			changed = true;
		}
	}

	return changed;
}

inline
bool DyssectController::update_relationship() 
{
	if(memcmp(newO, O, total_cores * total_cores * sizeof(uint32_t)) == 0) 
	{
		return false;
	}
	
	for(uint32_t w = 0; w < total_cores; w++) 
	{
		for(uint32_t e = 0; e < total_cores; e++) 
		{
			if(O[e*total_cores + w] == 0 && newO[e*total_cores + w] == 1) 
			{
				DyssectWorkingCore *working = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[w]));
				DyssectOffloadingCore *new_offloading = std::get<0>(offloading_cores[e]);
				
				if(!working->old_offloading) 
				{
					new_offloading->add_queue(working->get_queue());
					working->old_offloading = new_offloading;
				} else 
				{
					DyssectOffloadingCore *old_offloading = working->old_offloading;
					if(old_offloading == new_offloading) 
					{
						continue;
					}
				
					working->new_offloading = new_offloading;
					rte_atomic32_set(&working->transfer_offloading, 1);
				}
			}

			if(O[e*total_cores + w] == 1 && newO[e*total_cores + w] == 0) 
			{
				DyssectWorkingCore *working = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[w]));
				DyssectOffloadingCore *offloading = std::get<0>(offloading_cores[e]);

				if(working->old_offloading) 
				{
					offloading->remove_queue(working->get_queue());
				}
			}
		}
	}

	rte_memcpy(O, newO, total_cores * total_cores * sizeof(uint32_t));

	return true;
}	

inline
bool DyssectController::update_shards() 
{
        if(memcmp(A, newA, total_shards * total_cores * sizeof(uint32_t)) == 0) 
	{
                return false;
	}

        for(uint32_t s = 0; s < total_shards; s++) 
	{
                for(uint32_t w = 0; w < total_cores; w++) 
		{
                        if(newA[s*total_cores + w] == 1 && A[s*total_cores + w] == 0) 
			{
                                migration_shard(s, w, false);
                        }
                }
        }

        update_reta();

        for(uint32_t s = 0; s < total_shards; s++) 
	{
                for(uint32_t w = 0; w < total_cores; w++) 
		{
                        if(newA[s*total_cores + w] == 1 && A[s*total_cores + w] == 0) 
			{
                                migration_shard(s, w, true);
                        }
                }
        }

        rte_memcpy(A, newA, total_shards * total_cores * sizeof(uint32_t));

	return true;
}

void DyssectController::update_reta() 
{
	uint32_t transfers = 0;
	for(uint32_t s = 0; s < total_shards; s++) 
	{
		for(uint32_t w = 0; w < total_cores; w++) 
		{
			if(A[s*total_cores + w] != newA[s*total_cores + w])
			{
				transfers++;
			}

			if(newA[s*total_cores + w] == 1) 
			{
				for(uint32_t k = s; k < reta_size; k += total_shards)
				{
					reta_conf[k / RTE_RETA_GROUP_SIZE].reta[k % RTE_RETA_GROUP_SIZE] = w;
				}
			}
		}
	}

	transfers /= 2;

	if(transfers != 0) 
	{
		LOG(INFO) << "MIGRATIONS=" << transfers;
		int __attribute__((unused)) ret = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);
	}
}

inline
bool DyssectController::swap_shards() 
{
	for(uint32_t s = 0; s < total_shards; s++)
	{
		shards[s].use_2 ^= true;
	}

	last_totalpackets = total_packets;

	total_bytes = 0;
	total_packets = 0;

	for(uint32_t s = 0; s < total_shards; s++) 
	{
		shards[s].old_bytes = rte_atomic32_read(&shards[s].bytes);
		shards[s].old_packets = rte_atomic32_read(&shards[s].packets);
		rte_atomic32_clear(&shards[s].bytes);
		rte_atomic32_clear(&shards[s].packets);

		total_bytes += shards[s].old_bytes;
		total_packets += shards[s].old_packets;
	}

	return true;
}

inline 
bool DyssectController::order_shards() 
{
	total_flows = 0;
        
	for(uint32_t s = 0; s < total_shards; s++) 
	{
		HashTable *pflow;
		std::vector<DyssectState*> *vec = Controller::shards[s].ordered_flows;
                
		if(Controller::shards[s].use_2) 
		{
			while(rte_atomic32_read(&shards[s].ref_count_1) != 0) 
			{
			}
			pflow = Controller::shards[s].flows3;
		} else 
		{
			while(rte_atomic32_read(&shards[s].ref_count_2) != 0) 
			{
			}
			pflow = Controller::shards[s].flows3_2;
		}

		vec->clear();
		for(auto it = pflow->begin(); it != pflow->end(); it++) 
		{
			it->second->prob2 = it->second->prob;
			vec->push_back(it->second);
		}
                
		total_flows += pflow->size();
		std::sort(vec->begin(), vec->end(), sortByVal);

		double accum = 0.0;
		for(auto it = vec->begin(); it != vec->end(); it++) 
		{
			accum += (*it)->prob2;
			(*it)->cdf = accum;
		}
	}
	
	return true;
}

inline
bool DyssectController::volume_shards() 
{
	if(!last_totalpackets)
	{
		return false;
	}
	
	if(total_packets) 
	{
		Tr = processingtime_r(total_flows, W);
		Tp = processingtime_p(total_flows, W);

		for(uint32_t s = 0; s < total_shards; s++)
		{
			shards[s].V = (double)shards[s].old_packets * Tp * 1e6/SHORT_TIME; 
		}
	} else 
	{
		for(uint32_t s = 0; s < total_shards; s++)
		{
			shards[s].V = 0;
		}
	}
	
	return true;
}

inline
bool DyssectController::clear_flows() 
{
	for(uint32_t s = 0; s < total_shards; s++) 
	{
		if(Controller::shards[s].use_2) 
		{
			while(rte_atomic32_read(&shards[s].ref_count_1) != 0) 
			{
			}
			Controller::shards[s].flows3->clear();
		} else 
		{
			while(rte_atomic32_read(&shards[s].ref_count_2) != 0) 
			{
			}
			Controller::shards[s].flows3_2->clear();
		}
	}

	return true;
}

inline
void DyssectController::update_long_epoch() 
{
	bool ret = run_long_solver();

	if(ret) 
	{
		if(!total_packets) 
		{
			swap_shards();
			rte_atomic32_inc(Controller::epoch);
			clear_flows();

			return;
		}

		if(newW == W && newE == E) 
		{
			ret = run_short_solver(newW, newE);

			if(ret) 
			{
				bool changed_r = update_ratio();
				bool changed_relationship = update_relationship();
				bool changed_shards = update_shards();

				if(changed_shards || changed_r || changed_relationship) 
				{
					for(uint32_t i = 0; i < W; i++) 
					{
						DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));
						rte_atomic32_set(&w->controller_signal, 1);
					}
				}
			}
		} else 
		{
			ret = run_short_solver(newW, newE);
			if(ret) 
			{
				if(newE > E) 
				{
					enable_offloading_cores(E, newE);
				} else 
				{
					if(newE < E) 
					{
						mark_to_disable_offloading_cores(E, newE);
					}
				}

				if(newW > W) 
				{
					enable_working_cores(W, newW);
				} else 
				{
					if(newW < W) 
					{
						mark_to_disable_working_cores(W, newW);
					}
				}

				bool changed_r = update_ratio();
				bool changed_relationship = update_relationship();
				bool changed_shards = update_shards();

				if(changed_shards || changed_r || changed_relationship) 
				{
					for(uint32_t i = 0; i < W; i++) 
					{
						DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));
						rte_atomic32_set(&w->controller_signal, 1);
					}
				}
			
				if(newW < W)
				{
					disable_working_cores(W, newW);
				}

				if(newE < E)
				{
					disable_offloading_cores(E, newE);
				}

				W = newW;
				E = newE;
			}
		}
	}

	swap_shards();
	rte_atomic32_inc(Controller::epoch);
	clear_flows();
}

inline
void DyssectController::update_short_epoch(bool solver) {
	swap_shards();
	volume_shards();

	if(solver && total_packets) 
	{
		bool ret = run_short_solver(W, E);	

		if(ret) 
		{
			bool changed_r = update_ratio();
			bool changed_relationship = update_relationship();
			bool changed_shards = update_shards();

			if(changed_shards || changed_r || changed_relationship) 
			{
				for(uint32_t i = 0; i < W; i++) 
				{
					DyssectWorkingCore *w = reinterpret_cast<DyssectWorkingCore*>(std::get<0>(working_cores[i]));
					rte_atomic32_set(&w->controller_signal, 1);
				}
			}
		}
	}
		
	rte_atomic32_inc(Controller::epoch);
        
	order_shards();
	clear_flows();
}

bool DyssectController::run_short_solver(uint32_t w, uint32_t e) 
{
        int fd = open((const char*) solver_IN, O_CREAT | O_WRONLY, 0777);

        if(fd == -1)
	{
                return false;
	}
        
	uint32_t mode = SHORT;
	int __attribute__((unused)) n;

	n = write(fd, &mode, sizeof(uint32_t));
	n = write(fd, &w, sizeof(uint32_t));
	n = write(fd, &e, sizeof(uint32_t));
        n = write(fd, &total_cores, sizeof(uint32_t));
        n = write(fd, &total_shards, sizeof(uint32_t));

        n = write(fd, &Cap,  sizeof(double));
        n = write(fd, &Csp,  sizeof(double));
        n = write(fd, &SLOp, sizeof(double));
        n = write(fd, &Car,  sizeof(double));
        n = write(fd, &Csr,  sizeof(double));
        n = write(fd, &SLOr, sizeof(double));

        n = write(fd, &Tr, sizeof(double));
        n = write(fd, &Tp, sizeof(double));
       
	for(uint32_t s = 0; s < total_shards; s++)
	{
                n = write(fd, &shards[s].V, sizeof(double));
	}

        for(uint32_t s = 0; s < total_shards; s++)
	{
                n = write(fd, &shards[s].r, sizeof(double));
	}

        n = to_pipe(fd, (uint8_t*) A, total_shards * total_cores * sizeof(uint32_t));
        n = to_pipe(fd, (uint8_t*) O, total_cores  * total_cores * sizeof(uint32_t));

        close(fd);

        fd = open((const char*) solver_OUT, O_RDONLY);

        if(fd == -1)
	{
                return false;
	}

        int value;
        n = read(fd, &value, sizeof(int));

        if(value == 1) 
	{
                for(uint32_t s = 0; s < total_shards; s++) 
		{
			n = read(fd, &shards[s].r_new, sizeof(double));
		}
                
		n = from_pipe(fd, (uint8_t*) newA, total_shards * total_cores * sizeof(uint32_t));
                n = from_pipe(fd, (uint8_t*) newO, total_cores  * total_cores * sizeof(uint32_t));
	}

        close(fd);
        
	return value == 1;
}

bool DyssectController::run_long_solver() 
{
        int fd = open((const char*) solver_IN, O_CREAT | O_WRONLY, 0777);

        if(fd == -1)
	{
                return false;
	}
        
	uint32_t mode = LONG;
	int __attribute__((unused)) n;

	n = write(fd, &mode, sizeof(uint32_t));
        n = write(fd, &total_cores, sizeof(uint32_t));
        n = write(fd, &total_shards, sizeof(uint32_t));

        n = write(fd, &Cap,  sizeof(double));
        n = write(fd, &Csp,  sizeof(double));
        n = write(fd, &SLOp, sizeof(double));
        n = write(fd, &Car,  sizeof(double));
        n = write(fd, &Csr,  sizeof(double));
        n = write(fd, &SLOr, sizeof(double));

        n = write(fd, &Tr, sizeof(double));
        n = write(fd, &Tp, sizeof(double));

        for(uint32_t s = 0; s < total_shards; s++)
	{
                n = write(fd, &shards[s].V, sizeof(double));
	}

        n = to_pipe(fd, (uint8_t*) A, total_shards * total_cores * sizeof(uint32_t));
        n = to_pipe(fd, (uint8_t*) O, total_cores  * total_cores * sizeof(uint32_t));

        close(fd);

        fd = open((const char*) solver_OUT, O_RDONLY);

        if(fd == -1)
	{
                return false;
	}

        int value;
        n = read(fd, &value, sizeof(int));

        if(value == 1) 
	{
		n = read(fd, &newW, sizeof(uint32_t));
		n = read(fd, &newE, sizeof(uint32_t));
        }

        close(fd);

        return value == 1;
}

struct task_result DyssectController::RunTask(Context *, bess::PacketBatch *, void *) 
{
	if(!start)
	{
		return {.block = true, .packets = 0, .bits = 0};
	}

	uint64_t now = tsc_to_us(rdtsc());
	if(now > next_short) 
	{
		update_short_epoch(true);
		next_short = now + SHORT_TIME;
	}

	if(now > next_long) 
	{
		update_long_epoch();
		now = tsc_to_us(rdtsc());
		next_long = now + LONG_TIME;
		update_short_epoch(false);
		next_short = tsc_to_us(rdtsc()) + SHORT_TIME;
	}

	return {.block = true, .packets = 0, .bits = 0};
}

ADD_MODULE(DyssectController, "dyssectcontroller", "Controller of Dyssect")
