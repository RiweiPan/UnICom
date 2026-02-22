#!/bin/bash

# This script is used to build the Linux kernel for Bypassd.

SCRIPT_DIR=$(dirname $(realpath $0))
BASE_DIR=$SCRIPT_DIR/..
LINUX_DIR=$BASE_DIR/kernel/linux-6.5.1

# Install dependencies

# Build the kernel
pushd $LINUX_DIR
bash ./compile_install_kernel.sh
popd
