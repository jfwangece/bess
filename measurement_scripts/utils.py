
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
