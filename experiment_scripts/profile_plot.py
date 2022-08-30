import os
import sys

# Plot NF profile graph (pkt-size / pkt-rate / flow-count ~ latency)

def read_nf_profile(file_name):
    latency_results = []
    with open(file_name) as f:
        lines = f.readlines()
        for line in lines:
            if "Results" in line or "P50" in line or len(line) <= 80:
                continue
            nums = []
            for x in line.split(" "):
                if len(x.strip()) > 0:
                    nums.append(float(x))
            if len(nums) != 8:
                continue
            # pkt_size, pkt_rate, and flow_count
            inputs = nums[:3]
            # latency numbers are converted from nsec to usec
            outputs = [x / 1000.0 for x in nums[3:]]
            latency_results.append((inputs, outputs))
        f.close()
    return latency_results

def plot_nf_profile(file_name):
    latency_results = read_nf_profile(file_name)
    print("Total samples: {}".format(len(latency_results)))

    # Get all possible input values
    pkt_sizes = []
    pkt_rates = []
    flow_counts = []
    for exp in latency_results:
        inputs, outputs = exp
        ps, pr, fc = inputs
        if ps not in pkt_sizes:
            pkt_sizes.append(ps)
        if pr not in pkt_rates:
            pkt_rates.append(pr)
        if fc not in flow_counts:
            flow_counts.append(fc)
    pkt_sizes.sort()
    pkt_rates.sort()
    flow_counts.sort()

    # Vary flow counts
    for ps in pkt_sizes:
        for pr in pkt_rates:
            nums = []
            for exp in latency_results:
                inputs, outputs = exp
                if inputs[0] == ps and inputs[1] == pr:
                    nums.append(outputs[0])
            print("pkt size: %d; pkt rate: %d; %s" %(ps, pr, nums))
    return

def main():
    if len(sys.argv) == 1:
        print("usage: python profile_plot.py <profile-filename>")
        return

    file_name = sys.argv[1]
    plot_nf_profile(file_name)

if __name__ == "__main__":
    main()
