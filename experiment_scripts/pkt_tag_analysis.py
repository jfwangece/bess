import os
import sys

# Result 1:
# ncore: 165782; rcore: 92495
# ncore qlen: p10=43, p50=196, p95=487, p99=586 (ncore was having big queues)
# rcore qlen: p10=0, p50=0, p95=0, p99=1
# rcore idle: p10=0, p50=0, p95=1, p99=5 (rcore was delayed)


def main():
    # packet:2492, idle:4, qid:1234, qlen:255
    ncore = []
    rcore_idle = []
    rcore = []
    with open('out.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            fields = [x.strip() for x in line.split(',')]
            nums = []
            for field in fields:
                if len(field) > 0:
                    tmp = field.split(':')
                    nums.append(int(tmp[1]))
            if nums[2] == 1234:
                ncore.append(nums[3])
            else:
                rcore_idle.append(nums[1])
                rcore.append(nums[3])

    print("ncore: {}; rcore: {}".format(len(ncore), len(rcore)))

    ncore.sort()
    total_ncore_samples = len(ncore)
    p25_idx = int(total_ncore_samples * 0.25)
    p50_idx = int(total_ncore_samples * 0.5)
    p95_idx = int(total_ncore_samples * 0.95)
    p99_idx = int(total_ncore_samples * 0.99)
    print("ncore qlen: p10={}, p50={}, p95={}, p99={}".format(ncore[p25_idx], ncore[p50_idx], ncore[p95_idx], ncore[p99_idx]))

    rcore.sort()
    rcore_idle.sort()
    total_rcore_samples = len(rcore)
    p25_idx = int(total_rcore_samples * 0.25)
    p50_idx = int(total_rcore_samples * 0.5)
    p95_idx = int(total_rcore_samples * 0.95)
    p99_idx = int(total_rcore_samples * 0.99)
    print("rcore qlen: p10={}, p50={}, p95={}, p99={}".format(rcore[p25_idx], rcore[p50_idx], rcore[p95_idx], rcore[p99_idx]))
    print("rcore idle: p10={}, p50={}, p95={}, p99={}".format(rcore_idle[p25_idx], rcore_idle[p50_idx], rcore_idle[p95_idx], rcore_idle[p99_idx]))
    return


if __name__ == "__main__":
    main()
