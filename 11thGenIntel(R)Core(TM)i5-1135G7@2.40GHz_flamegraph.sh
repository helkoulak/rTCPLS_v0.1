MIN=400MHz
MAX=4200MHz
SET_MIN=2799MHz
SET_MAX=2800MHz
BENCH=$1
PROFILE=$2

sudo cpupower -c 0 frequency-set -d $SET_MIN -u $SET_MAX -g performance
taskset -c 0 cargo flamegraph --bench $BENCH --profile $PROFILE
sudo cpupower -c 0 frequency-set -d $MIN -u $MAX -g powersave