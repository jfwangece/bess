import os
import sys
from bess_runner import run_test
from plot_profile import plot_nf_profile

pkt_size_samples = [1050]
pkt_rate_samples = range(100000, 1100000, 100000)
flow_count_samples = range(1000, 21000, 500)

def main():
    run_test("nfvctrl/profile_chain4", pkt_size_samples, pkt_rate_samples, flow_count_samples)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    else:
        print(sys.argv)
        if sys.argv[1] == "plot" and len(sys.argv) == 3:
            file_name = sys.argv[2]
            plot_nf_profile(file_name)
        elif sys.argv[1] == "exp" and len(sys.argv) == 3:
            exp_name = "nfvctrl/%s" %(sys.argv[2])
            run_test(exp_name, pkt_size_samples, pkt_rate_samples, flow_count_samples)
        elif sys.argv[1] == "est":
            num_groups = len(pkt_size_samples) * len(pkt_rate_samples) * len(flow_count_samples)
            est_time = num_groups * 30.0 / 3600
            print("Total exp groups: {}; Est time: {} hour(s)".format(num_groups, est_time))
        else:
            print("Unknown request: {}", sys.argv[1])
