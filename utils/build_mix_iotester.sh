#!/bin/bash

SCRIPT_DIR=$(dirname $(realpath $0))
BASE_DIR=$SCRIPT_DIR/../
IOTESTER_DIR=$BASE_DIR/workloads/mix-io-tester

pushd $IOTESTER_DIR

make -j $(nproc)

popd
