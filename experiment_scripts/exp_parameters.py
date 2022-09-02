
## Experiment 1: fix packet size and packet rate; vary flow count;
pkt_size_samples = [500]
pkt_rate_samples = [1600000]
flow_count_samples = range(300, 3700, 300)

## Experiment 2: fix packet rate and flow count; vary packet size;
# Chain 2
pkt_size_samples = range(150, 1500, 150)
pkt_rate_samples = [160000]
flow_count_samples = [1000, 2000]

# Chain 4
pkt_size_samples = range(150, 1500, 150)
pkt_rate_samples = [1600000]
flow_count_samples = [1000, 2000]

## Long-term NF profiling
# Chain 4
pkt_size_samples = range(150, 1500, 300)
pkt_rate_samples = range(1600000, 2400000, 50000)
flow_count_samples = range(900, 3400, 300)
