
# Cluster CPU core usage information
class Snapshot(object):
    def __init__(self, epoch, core, rate):
        self._epoch_id = epoch
        self._core_cnt = core
        self._pkt_rate = rate

class CoreSnapshot(object):
    def __init__(self, epoch, active, slo, aflow, bflow, rate):
        self._epoch_id = epoch
        self._active = active
        self._slo_violations = slo
        self._active_flow_cnt = aflow
        self._burst_flow_cnt = bflow
        self._pkt_rate = rate

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

            data = [float(m.split(':')[1]) for m in line.split(',')]
            ss = CoreSnapshot(data[0], data[1], data[2], data[3], data[4], data[5])
            core_snapshots.append(ss)
        f.close()
    return core_snapshots

