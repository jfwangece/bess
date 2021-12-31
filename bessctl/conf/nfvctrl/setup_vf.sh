#!/bin/bash

INTERFACE="enp94s0"
PCI_DEVICE="0000:5e:00.0"

echo "interface=${INTERFACE}"
echo "pcie=${PCI_DEVICE}"

echo "Configures MAC address for vf..."
sudo ip link set dev ${INTERFACE} down
sudo ip link set dev ${INTERFACE} up

echo "Set up SR-IOV for the target NIC."
echo 15 | sudo tee /sys/bus/pci/devices/${PCI_DEVICE}/sriov_numvfs

ip link show

# turn off rx filters
sudo ethtool -K ${INTERFACE} ntuple off
# turn off checksuming
sudo ethtool -K ${INTERFACE} rx off tx off tso off
# turn off pause frames
sudo ethtool -A ${INTERFACE} rx off tx off
# set the maximum queue size
sudo ethtool -G ${INTERFACE} rx 4096 tx 4096

# Note: this does not work for Mellanox ConnectX-5
# sudo ip link set ${INTERFACE} vf 0 mac 00:00:00:00:00:01
# sudo ip link set ${INTERFACE} vf 1 mac 00:00:00:00:00:02
# sudo ip link set ${INTERFACE} vf 2 mac 00:00:00:00:00:03
# sudo ip link set ${INTERFACE} vf 3 mac 00:00:00:00:00:04
# sudo ip link set ${INTERFACE} vf 4 mac 00:00:00:00:00:05
# sudo ip link set ${INTERFACE} vf 5 mac 00:00:00:00:00:06
# sudo ip link set ${INTERFACE} vf 6 mac 00:00:00:00:00:07
# sudo ip link set ${INTERFACE} vf 7 mac 00:00:00:00:00:08
# sudo ip link set ${INTERFACE} vf 8 mac 00:00:00:00:00:09
# sudo ip link set ${INTERFACE} vf 9 mac 00:00:00:00:00:10
# sudo ip link set ${INTERFACE} vf 10 mac 00:00:00:00:00:11
# sudo ip link set ${INTERFACE} vf 11 mac 00:00:00:00:00:12
# sudo ip link set ${INTERFACE} vf 12 mac 00:00:00:00:00:13
# sudo ip link set ${INTERFACE} vf 13 mac 00:00:00:00:00:14
# sudo ip link set ${INTERFACE} vf 14 mac 00:00:00:00:00:15

# Mellanox ConnectX-5 VFs
# 0a:14:69:37:5f:f2
# 82:a3:ae:74:72:30
# a2:87:fd:f8:72:21
# 2e:c7:8b:7b:8d:a8
# 2a:9d:fd:13:15:01
# 32:a5:0f:e0:04:0b
# 06:8a:62:fb:51:51

sudo ip link set ${INTERFACE} vf 0 spoofchk on

echo "Disables ASLR..."
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

echo "Sets up Hugepages..."
echo 2048 | sudo tee /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages
echo 2048 | sudo tee /sys/devices/system/node/node1/hugepages/hugepages-2048kB/nr_hugepages
