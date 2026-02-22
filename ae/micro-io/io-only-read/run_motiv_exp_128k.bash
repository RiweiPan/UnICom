SCRIPT_PATH=$(realpath $0)
SCRIPT_DIR=$(dirname ${SCRIPT_PATH})
NAP_ROOT_DIR=$SCRIPT_DIR/../../../

source $NAP_ROOT_DIR/nap_common_env.sh  # load common environment variables
cp ../run_exp_once.bash .

# exp settings
FILE_NAME=$MOUNT_DIR/mix-io-eval
NR_COUNTER_THREADS=0
NR_QUEUE=8
IO_SIZE=128k
RESULT_DIR=no_limit_128k-q$NR_QUEUE-new-nap-impl

SHARED_OPTIONS="-z $IO_SIZE -d $NVME_DEV -p $MOUNT_DIR -f $FILE_NAME -n $NR_COUNTER_THREADS -s $RESULT_DIR -q $NR_QUEUE"


# bash run_exp_once.bash -t 1 -m irq -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 4 -m irq -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 8 -m irq -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 16 -m irq -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 32 -m irq -c 16-31 $SHARED_OPTIONS

# bash run_exp_once.bash -t 1 -m poll -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 4 -m poll -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 8 -m poll -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 16 -m poll -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 32 -m poll -c 16-31 $SHARED_OPTIONS

# bash run_exp_once.bash -t 1 -m nap -c 16-30 $SHARED_OPTIONS
# bash run_exp_once.bash -t 4 -m nap -c 16-30 $SHARED_OPTIONS
# bash run_exp_once.bash -t 8 -m nap -c 16-30 $SHARED_OPTIONS
# bash run_exp_once.bash -t 16 -m nap -c 16-30 $SHARED_OPTIONS
# bash run_exp_once.bash -t 32 -m nap -c 16-30 $SHARED_OPTIONS

# bash run_exp_once.bash -t 1 -m uring -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 4 -m uring -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 8 -m uring -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 16 -m uring -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 32 -m uring -c 16-31 $SHARED_OPTIONS

# bash run_exp_once.bash -t 1 -m uring-shared -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 4 -m uring-shared -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 8 -m uring-shared -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 16 -m uring-shared -c 16-31 $SHARED_OPTIONS
# bash run_exp_once.bash -t 32 -m uring-shared -c 16-31 $SHARED_OPTIONS


