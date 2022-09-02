import os
import sys
from bess_runner import run_test
from profile_plot import plot_nf_profile

pkt_size_samples = range(150, 1500, 150)
pkt_rate_samples = [140000]
flow_count_samples = [1000, 2000]

# pkt_size_samples = range(150, 1500, 300)
# pkt_rate_samples = range(1500000, 2500000, 50000)
# flow_count_samples = range(600, 3000, 200)

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
