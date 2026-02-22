#!/bin/bash
SCRIPT_PATH=$(realpath $0)
BASE_DIR=$(dirname ${SCRIPT_PATH})/../
TOOLS_DIR=$(dirname ${SCRIPT_PATH})/tools

DEV_NAME=$1

sudo $TOOLS_DIR/config_nap $DEV_NAME 0 # stop dedicated thread

sudo rmmod nap.ko

# Deallocate hugepages for DMA buffers
sudo bash -c "echo 0 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"