core_snapshot_fields = [
    'epoch', 'size', 'core',
    'slo', 'delaye', 'delaym',
    'flowa', 'flowb', 'rate', 'pktp', 'pktq',
]

# Cluster CPU core usage information
class Snapshot(object):
    def __init__(self, epoch, core, rate):
        self._epoch_id = epoch
        self._core_cnt = core
        self._pkt_rate = rate

class CoreSnapshot(object):
    def __init__(self, epoch_info):
        ''' |epoch_info| is a dictionary that contains all fields in |core_snapshot_fields|
        '''
        self._epoch_id = epoch_info['epoch']
        self._epoch_size = epoch_info['size']
        self._active = epoch_info['core']
        self._slo_violations = epoch_info['slo']
        self._delay_errors = epoch_info['delaye']
        self._delay_max = epoch_info['delaym']
        self._active_flow_cnt = epoch_info['flowa']
        self._burst_flow_cnt = epoch_info['flowb']
        self._pkt_rate = epoch_info['rate']
        self._pkt_processed = epoch_info['pktp']
        self._pkt_queued = epoch_info['pktq']

class SLOEvent(object):
    def __init__(self, epoch_cnt, pkt_cnt):
        self._epoch_cnt = epoch_cnt
        self._pkt_cnt = pkt_cnt

def read_cluster_snapshot(file_name):
    cluster_snapshots = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if not ('epoch' in line and 'core' in line and 'rate' in line):
                continue

            data = [float(m.split(':')[1]) for m in line.split(',')]
            ss = Snapshot(data[0], data[1], data[2])
            cluster_snapshots.append(ss)
        f.close()
    return cluster_snapshots

def read_core_snapshot(file_name):
    core_snapshots = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if not ('epoch' in line and 'slo' in line and 'rate' in line):
                continue

            data = [(m.split(':')[0].strip(), float(m.split(':')[1])) for m in line.split(',')]
            epoch_info = {}
            for field,val in data:
                epoch_info[field] = val

            ss = CoreSnapshot(epoch_info)
            core_snapshots.append(ss)
        f.close()
    return core_snapshots

def slo_violation_analysis(snapshots):
    slo_vio_nodes = []
    non_slo_vio_nodes = []

    n = len(snapshots)
    for sidx in range(1, n-2):
        is_both = 0
        if snapshots[sidx]._slo_violations == 0:
            is_both += 1
            non_slo_vio_nodes.append((snapshots[sidx]._active_flow_cnt, snapshots[sidx]._pkt_processed))
        if snapshots[sidx]._slo_violations > 0:
            is_both += 1
            slo_vio_nodes.append((snapshots[sidx]._active_flow_cnt, snapshots[sidx]._pkt_processed))

        if is_both == 2:
            raise Exception("Error: an epoch is both slo-violating and non-slo-violating..")

    return (slo_vio_nodes, non_slo_vio_nodes)

def get_short_term_profile(nodes):
    """ Each node is a tuple (flow count, packet count).
    Then, we want to find: given a flow count, the max possible packet count
    that a core can process within an epoch.
    Method:
    1. sort nodes according to their flow counts;
    2. start from the highest flow count, update the max packet count;
    3. set each flow count to be the current max packet count;
    """
    sorted_nodes = sorted(nodes, key=lambda x: x[0])
    max_flow = int(sorted_nodes[-1][0])
    curr_max_pkt_cnt = int(sorted_nodes[-1][1])
    short_term_profile = []
    # print(sorted_nodes)

    fc_to_pkt = {}
    for flow_count, pkt_count in sorted_nodes:
        flow_count = int(flow_count)
        if flow_count not in fc_to_pkt:
            fc_to_pkt[flow_count] = int(pkt_count)
        else:
            fc_to_pkt[flow_count] = max(fc_to_pkt[flow_count], int(pkt_count))

    for i in reversed(range(1, max_flow)):
        if i in fc_to_pkt:
            curr_max_pkt_cnt = max(curr_max_pkt_cnt, fc_to_pkt[i])
        short_term_profile.append((i, curr_max_pkt_cnt))

    # Sort based on the flow count (x-axis)
    short_term_profile = sorted(short_term_profile, key=lambda x: x[0])
    return short_term_profile
