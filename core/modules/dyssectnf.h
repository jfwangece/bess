#ifndef BESS_MODULES_DYSSECTNF_H_
#define BESS_MODULES_DYSSECTNF_H_

#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_hash_crc.h>
#include <google/dense_hash_map>

#include "../module.h"
#include "../kmod/llring.h"

#include "dyssectworking.h"
#include "dyssectoffloadingcore.h"

#define L3_OFFSET		0
#define L4_OFFSET		8
#define FLOW_SIZE		12
#define	PAYLOAD_OFFSET		16
#define	DYSSECT_OFFSET		24

struct DyssectFlow 
{
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t src_addr;
        uint32_t dst_addr;
	uint32_t hash_value;

        struct Hash 
	{
                std::size_t operator()(const DyssectFlow &f) const 
		{
			return f.hash_value;
                }
        };

        struct EqualTo 
	{
                bool operator()(const DyssectFlow &a, const DyssectFlow &b) const 
		{
                        return !memcmp((void*) &a, (void*) &b, FLOW_SIZE);
                }
        };
};

struct DyssectState 
{
        double cdf;
        double prob;
        double prob2;
	bool priority;
	bool offloaded;
        uint32_t epoch;
        uint32_t shard;
        uint32_t bytes;
        uint32_t packets;
        uint32_t old_bytes;
        uint32_t old_packets;

	DyssectFlow flow;

        void **global_state;

        struct Hash 
	{
                std::size_t operator()(const DyssectState *s) const 
		{
			return s->flow.hash_value;
                }
        };

        struct EqualTo 
	{
                bool operator()(const DyssectState *a, const DyssectState *b) const 
		{
			return !memcmp((void*) &(a->flow), (void*) &(b->flow), FLOW_SIZE);
                }
        };
};

using HashTable  = google::dense_hash_map<DyssectFlow, DyssectState*, DyssectFlow::Hash, DyssectFlow::EqualTo>;
using HashTable2 = google::dense_hash_map<DyssectState*, uint32_t>;

struct ShardInfo 
{
        double r;
        double V;
	bool use_2;
        rte_atomic32_t bytes;
        rte_atomic32_t packets;
        uint32_t old_bytes;
        uint32_t old_packets;

	rte_atomic32_t pause;
	rte_atomic32_t ref_count_1;
	rte_atomic32_t ref_count_2;

	std::vector<DyssectState*> *ordered_flows;

        double r_new;
        DyssectWorking *owner;
        DyssectWorking *owner_new;
        HashTable *table;
        llring *local_queue;
        HashTable2 *flows;
        HashTable *flows3;
        HashTable *flows3_2;
};

class DyssectNF : public Module 
{
	public:
		DyssectNF() : Module() { }

		typedef uint32_t state_handle;
		typedef void StateNF;

		state_handle handle;

		inline state_handle _init_nf_state() 
		{
			return handle;
		}

		template <typename T>
		inline bool _insert(state_handle handle, bess::Packet* pkt, T* state) 
		{
			void **global_state = _get_attr_with_offset<void**>(DYSSECT_OFFSET, pkt);

		        if(global_state[handle])
			{
                		return false;
			}

		        global_state[handle] = (T*) state;

		        return true;
		}

		template <typename T>
		inline bool _delete(state_handle handle, bess::Packet* pkt) 
		{
			void **global_state = _get_attr_with_offset<void**>(DYSSECT_OFFSET, pkt);

			T *state = reinterpret_cast<T*>(global_state[handle]);

		        if(!state)
			{
                		return false;
			}

        		delete state;
			global_state[handle] = nullptr;

        		return true;
		}

		template <typename T>
		inline T* _lookup(state_handle handle, bess::Packet *pkt) 
		{
			void **global_state = _get_attr_with_offset<void**>(DYSSECT_OFFSET, pkt);

			return (T*) global_state[handle];
		}
};

#endif //BESS_MODULES_DYSSECTNF_H_
