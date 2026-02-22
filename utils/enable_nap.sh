#!/bin/bash
SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname ${SCRIPT_PATH})/../
TOOLS_DIR=$(dirname ${SCRIPT_PATH})/tools

# Check that mount point is passed to this script
if [ $# -ne 4 ] && [ $# -ne 5 ]; then
    echo "Usage: $0 <device_name> <mount point> <queue cnt> <mode> <ctype>; <ctype> is optional"
    exit 1
fi

DEV_NAME=$1
MOUNT_POINT=$2
QUEUE_CNT=$3
MODE=$4
if [ $# -eq 5 ]; then
    CTYPE=$5
else
    CTYPE="default"
fi

if [ $MODE != "nap" ] && [ $MODE != "poll" ]; then
    echo "IO Mode must be nap or poll"
    exit 1
fi

# Check if the Bypassd module is installed
if lsmod | grep -wq 'nap'; then
    echo "NAP module is already installed"
else
    pushd ${BASE_DIR}/kernel/nap
    if [ $MODE == "nap" ]; then
        make NAP_POLL=1 host
    else
        make host
    fi
    sudo insmod nap.ko
    popd
fi

if [ ! -f $TOOLS_DIR/config_nap ]; then
    pushd $TOOLS_DIR
    make config_nap
    popd
fi

pushd ${BASE_DIR}/nap_ulib
sed -i "/char DEVICE_DIR/c\const char DEVICE_DIR[32] = \"${MOUNT_POINT}\";" ulib_shim.c
ULIB_OPS=""
make clean
if [ $CTYPE == "rocksdb" ]; then
    ULIB_OPS="RKDB=1"
fi
if [ $MODE == "nap" ]; then
    ULIB_OPS="$ULIB_OPS NAP_POLL=1"
fi
make $ULIB_OPS
popd


DEV_ID=$(basename $DEV_NAME)
sudo bash -c "echo 1 > /proc/fs/ext4/${DEV_ID}/nap_map_enable"
sudo bash -c "echo 1 > /proc/fs/ext4/${DEV_ID}/swiftcore_dram_pt"
sudo bash -c "echo 4 > /proc/fs/swiftcore/swiftcore_filesize_limit"

# Allocate hugepages for DMA buffers
sudo bash -c "echo 128 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"

sleep 1


sudo $TOOLS_DIR/config_nap $DEV_NAME 1 $QUEUE_CNT # start dedicated thread

if [ ! $? -eq 0 ]; then
    sudo rmmod nap
  exit 1
fi
