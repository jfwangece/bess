#ifndef BESS_MODULES_CONTROLLER_H_
#define BESS_MODULES_CONTROLLER_H_

#include <vector>
#include <math.h>
#include <float.h>
#include <algorithm>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_memory.h>

#include "../port.h"
#include "../module.h"
#include "../drivers/pmd.h"
#include "../kmod/llring.h"
#include "../module_graph.h"
#include "../pb/module_msg.pb.h"

#include "dyssectworking.h"
#include "dyssectoffloadingcore.h"
#include "dyssectnf.h"

#define LONG 		0
#define SHORT 		1
#define SCALE 		1.5
#define EPSILON 	0.0000000001f
#define LONG_TIME 	1e6 
#define SHORT_TIME 	0.1e6
#define RETA_CONF_SIZE     (ETH_RSS_RETA_SIZE_512 / RTE_RETA_GROUP_SIZE)

class Controller : public Module 
{
	public:
		static ShardInfo *shards;
		static uint32_t total_shards;
		static rte_atomic32_t *epoch;
        	static const gate_idx_t kNumIGates = 0;
        	static const gate_idx_t kNumOGates = 0;

		Controller() : Module() { }

		static bool sortByVal(DyssectState*, DyssectState*);
};

#endif // BESS_MODULES_CONTROLLER_H_
