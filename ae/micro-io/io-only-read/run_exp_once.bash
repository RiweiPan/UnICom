#!/bin/bash

SCRIPT_PATH=$(realpath $0)
SCRIPT_DIR=$(dirname ${SCRIPT_PATH})
NAP_ROOT_DIR=$SCRIPT_DIR/../../../
USERLIB_DIR=$NAP_ROOT_DIR/userLib
NAP_USERLIB_DIR=$NAP_ROOT_DIR/nap_ulib
FIO_DIR=$NAP_ROOT_DIR/workloads/mix-io-tester
DEFAULT_QLEN=42
QLEN=$DEFAULT_QLEN
BYPASSD_QLEN=$DEFAULT_QLEN
DEFAULT_IOREQUESTSIZE=4k
IOREQUESTSIZE=$DEFAULT_IOREQUESTSIZE
NOSETUP_CPUENV="set"
NR_THREADS=1
NR_CT_THREADS=0
FILE_SIZE=1G
IO_ENGINE="psync"
RWMODE=randread
TESTPATH=fio-rand-read
FIORUNTIME=10

# set -x

set_eval_env() {
    while getopts 'hp:d:m:t:s:c:n:z:q:y:r:f:v:w:b:"' OPTION; do
        case "$OPTION" in
            h)
                echo "Usage: $(basename $0) [-h] [-d <device>] [-c <cpu>] [-f <freq>]"
                echo "  -h  Display this help message"
                echo "  -d  Device to run the benchmark. e.g., nvme0n1"
                echo "  -p  Dir to run the benchmark, e.g., /mnt/nvme"
                echo "  -m  I/O completion mode, e.g., poll/irq/nap"
                echo "  -t  The number of I/O threads, e.g., if not set, using the default settings"
                echo "  -n  The number of I/O counter threads, e.g., if not set, using the default settings"
                echo "  -s  The timestamp mark for the evaluation"
                echo "  -c  The CPU cores allowed for the evaluation"
                echo "  -z  The size of the I/O request"
                echo "  -q  The number of queues for the evaluation"
                echo "  -y  The process mode for the evaluation"
                echo "  -r  The runtime for the evaluation"
                echo "  -v  Does not run the cpu env setup"
                echo "  -w  read/write mode for the evaluation"
                echo "  -f  The filename/dirname for the evaluation"
                echo "  -b  The bypassd queue length for the evaluation"
                exit 1
                ;;
            d)
                DEV_NAME="$OPTARG"
                ;;
            p)
                MOUNT_POINT="$OPTARG"
                ;;
            t)
                NR_THREADS="$OPTARG"
                ;;
            n)
                NR_CT_THREADS="$OPTARG"
                ;;
            m)
                IOMODE="$OPTARG"
                ;;
            s)
                TSMARK="$OPTARG"
                ;;
            c)
                CPUALLOWED="$OPTARG"
                ;;
            z)
                IOREQUESTSIZE="$OPTARG"
                ;;
            q)
                QLEN="$OPTARG"
                ;;
            b)
                BYPASSD_QLEN="$OPTARG"
                ;;
            y)
                PROCMODE="$OPTARG"
                ;;
            r)
                FIORUNTIME="$OPTARG"
                ;;
            v)
                NOSETUP_CPUENV="$OPTARG"
                ;;
            w)
                RWMODE="$OPTARG"
                ;;
            f)
                TESTPATH="$OPTARG"
                ;;
            ?)
                echo "Invalid option: -$OPTARG" >&2
                exit 1
                ;;
        esac
    done
    return
}

### run the script
set_eval_env "$@" # Parse the arguments

if [ -z "$DEV_NAME" ] || [ -z "$MOUNT_POINT" ] || [ -z "$IOMODE" ]; then
    echo "You should set at least <device name>, <mount point>, <I/O mode> and <fio workload path>"
    exit 1
fi

if [ "$IOMODE" != "poll" ] && [ "$IOMODE" != "irq" ] &&  [ $IOMODE != "nap" ] &&  [ $IOMODE != "uring" ] &&  [ $IOMODE != "uring-shared" ]; then
    echo "IO Mode must be poll/irq/nap/uring/uring-shared"
    exit 1
fi

if [ "$RWMODE" != "randread" ] && [ "$RWMODE" != "randwrite" ] && [ "$RWMODE" != "seqread" ] && [ "$RWMODE" != "seqwrite" ]; then
    echo "RW Mode must be randread/randwrite/seqread/seqwrite"
    exit 1
fi

# Mount the device (if not already mounted)
bash $NAP_ROOT_DIR/utils/mount_dev.sh $DEV_NAME $MOUNT_POINT

# check if the TESTPATH exists
# TESTPATH could be directory or file
if [ ! -d "$TESTPATH" ] && [ ! -f "$TESTPATH" ]; then
    echo "Test path $TESTPATH does not exist. Please check the path."
    exit 1
fi

# Disable CPU Turbo and Hyperthreading
if [ "$NOSETUP_CPUENV" == "set" ]; then
    bash ${NAP_ROOT_DIR}/utils/setup_cpu_env.sh disable
fi

# setting up the output directory
RESULTS_DIR=$SCRIPT_DIR/results/$TSMARK
if [ ! -d ${RESULTS_DIR} ]; then
    mkdir -p $SCRIPT_DIR/results/$TSMARK
fi

# enable specific I/O mode
if [ "$IOMODE" == "uring" ] || [ "$IOMODE" == "uring-shared" ]; then
    IO_ENGINE=$IOMODE
fi

BASE_DEV_NAME=$(basename $DEV_NAME)
export NAP_DEVPATH="$BASE_DEV_NAME"

# enable specific I/O mode
if [ "$IOMODE" == "nap" ]; then
    # Enable nap and nr_queues for users
    bash ${NAP_ROOT_DIR}/utils/enable_nap.sh $DEV_NAME $MOUNT_POINT $QLEN nap
elif [ "$IOMODE" == "poll" ]; then
    bash ${NAP_ROOT_DIR}/utils/enable_nap.sh $DEV_NAME $MOUNT_POINT $BYPASSD_QLEN poll # 42 is the default setting of Bypassd
fi

echo "IOMODE: $IOMODE CPUALLOWED: $CPUALLOWED"

FIO_OPTIONS="--direct-io \
                --io-engine=${IO_ENGINE} \
                --path=${TESTPATH} \
                --file-size=${FILE_SIZE} \
                --num-threads=${NR_THREADS} \
                --num-counter-threads=${NR_CT_THREADS} \
                --cpu-affinity=${CPUALLOWED} \ 
                --io-mode=${RWMODE} \
                --runtime=${FIORUNTIME} \
                --latency-stats"

# handle mix I/O sizes
if [ -n "$IOREQUESTSIZE" ]; then
    # does this string contains ":"?
    if [[ $IOREQUESTSIZE == *":"* ]]; then
        FIO_OPTIONS="${FIO_OPTIONS} --io-size-ratio=${IOREQUESTSIZE}"
    else
        FIO_OPTIONS="${FIO_OPTIONS} --io-size=${IOREQUESTSIZE}"
    fi
fi

# run mix_io_tester experiments!
if [ $IOMODE == "poll" ] || [ $IOMODE == "nap" ]; then
    LD_PRELOAD_PATH=${NAP_USERLIB_DIR}/libnapshim.so
    sudo LD_PRELOAD=$LD_PRELOAD_PATH NAP_DEVPATH="$BASE_DEV_NAME" $FIO_DIR/mix_io_tester ${FIO_OPTIONS} 2>&1 | tee $SCRIPT_DIR/results/$TSMARK/${IOMODE}_${NR_THREADS}_${NR_CT_THREADS}.out
elif [ $IOMODE == "irq" ] || [ "$IOMODE" == "uring" ] || [ "$IOMODE" == "uring-shared" ]; then
    sudo $FIO_DIR/mix_io_tester ${FIO_OPTIONS} 2>&1 | tee $SCRIPT_DIR/results/$TSMARK/${IOMODE}_${NR_THREADS}_${NR_CT_THREADS}.out
fi

if [ "$IOMODE" == "nap" ]; then
    bash ${NAP_ROOT_DIR}/utils/disable_nap.sh $DEV_NAME
elif [ "$IOMODE" == "poll" ]; then
    bash ${NAP_ROOT_DIR}/utils/disable_nap.sh $DEV_NAME
fi

# Enable CPU Turbo and Hyperthreading
if [ "$NOSETUP_CPUENV" == "set" ]; then
    bash ${NAP_ROOT_DIR}/utils/setup_cpu_env.sh enable
fi

sleep 10
