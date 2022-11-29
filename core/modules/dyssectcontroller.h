#ifndef _BESS_MODULES_CONTROLLERPRIORITY_H_
#define _BESS_MODULES_CONTROLLERPRIORITY_H_

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dyssectworking.h"
#include "dyssectworkingcore.h"
#include "dyssectoffloadingcore.h"
#include "controller.h"

class DyssectController final : public Controller 
{
private:

	bool start;
	Port *port;
	uint32_t W;
	uint32_t E;
	uint32_t *A;
	uint32_t *O;
	char *solver_IN;
	char *solver_OUT;
	uint32_t port_id;
	uint32_t reta_size;
	uint64_t next_long;
	uint64_t next_short;
	uint32_t sfc_length;
	uint32_t total_bytes;
	uint32_t total_flows;
	uint32_t total_cores;
	uint32_t total_packets;
	struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

	std::deque<uint32_t> availables;
	std::vector<std::tuple<DyssectWorking*, bess::TrafficClass*, uint32_t> > working_cores;
	std::vector<std::tuple<DyssectOffloadingCore*, bess::TrafficClass*, uint32_t> > offloading_cores;

	double Tr;
	double Tp;
	double Car;
	double Csr;
	double SLOr;
	double Cap;
	double Csp;
	double SLOp;
	uint64_t last_totalpackets;

	uint32_t newW;
	uint32_t newE;
	uint32_t *newA;
	uint32_t *newO;

	void update_reta();
	void update_long_epoch();
	void update_short_epoch(bool);

	bool clear_flows();
	bool swap_shards();
	bool order_shards();
	bool volume_shards();

	bool run_long_solver();
	bool run_short_solver(uint32_t, uint32_t);

	bool update_ratio();
	bool update_shards();
	bool update_relationship();
	void migration_shard(uint32_t s, uint32_t w, bool send_signal);
	
	void enable_working_cores(uint32_t from, uint32_t to);
	void enable_offloading_cores(uint32_t from, uint32_t to);
	
	void disable_working_cores(uint32_t from, uint32_t to);
	void disable_offloading_cores(uint32_t from, uint32_t to);

	void mark_to_disable_working_cores(uint32_t from, uint32_t to);
	void mark_to_disable_offloading_cores(uint32_t from, uint32_t to);

public:

        static const Commands cmds;
        static const gate_idx_t kNumIGates = 0;
        static const gate_idx_t kNumOGates = 0;

        DyssectController() : Controller() { }

	CommandResponse CommandSetCAp(const bess::pb::CVArg&);
	CommandResponse CommandSetCSp(const bess::pb::CVArg&);
	CommandResponse CommandSetCAr(const bess::pb::CVArg&);
	CommandResponse CommandSetCSr(const bess::pb::CVArg&);
        CommandResponse CommandStart(const bess::pb::EmptyArg&);
	CommandResponse CommandSetSLOr(const bess::pb::SLOArg&);
	CommandResponse CommandSetSLOp(const bess::pb::SLOArg&);
        CommandResponse Init(const bess::pb::DyssectControllerArg&);
        CommandResponse CommandAddDyssectWorkingCore(const bess::pb::AddCoreArg&);
        CommandResponse CommandAddDyssectOffloadingCore(const bess::pb::AddCoreArg&);

        struct task_result RunTask(Context *ctx, bess::PacketBatch *, void *);
};

#endif // _BESS_MODULES_CONTROLLERPRIORITY_H_
