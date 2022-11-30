#!/bin/bash

set -e

usage() {
        echo "run_dyssect.sh -s <SLO> -p <PARA>"
}

TARGET_SLO="100000"
TARGET_PARA="1.0"

while getopts "h?s:p:" opt; do
    case "${opt}" in
        h|\?)
            usage
            exit 0
            ;;
        s)
            TARGET_SLO=${OPTARG}
            ;;
        p)
            TARGET_PARA=${OPTARG}
            ;;
    esac
done

if [ -z ${TARGET_SLO} ]; then
        usage
        exit -1
fi
if [ -z ${TARGET_PARA} ]; then
        usage
        exit -1
fi

SHARDS=64                           # The number of shards
SFC_LENGTH=3                        # The length of the Service Function Chain
CONTROLLER_CORE=30                  # The core to assign to Dyssect Controller
SOLVER_CORE=31                      # The core to assign to optimizer process
SCRIPT_NAME="cloud_dyssect_chain4"  # The name of BESS configuration script (in the bessctl/conf/ directory)

echo "Killing previous processes..."
pkill -9 bessd 1>/dev/null 2>/dev/null
pkill -9 solver 1>/dev/null 2>/dev/null

echo "Starting BESS daemon..."
sudo ./bessctl/bessctl daemon start

echo "Running the optimizer..."
taskset -c ${SOLVER_CORE} ./solver 1>/dev/null 2>/dev/null &

echo "Running the Dyssect..."
sudo ./bessctl/bessctl run nfvctrl/${SCRIPT_NAME} BESS_SLO=${TARGET_SLO}, SHARDS=${SHARDS}, SFC_LENGTH=${SFC_LENGTH}, CONTROLLER_CORE=${CONTROLLER_CORE}, INPUT_PARA=${TARGET_PARA}
