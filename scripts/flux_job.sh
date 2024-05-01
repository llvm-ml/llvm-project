#!/usr/bin/env bash

set -e
set -x

module load python/3.10.8

START=0
END=7000

NODES="$1"
TIMEOUT="$2"
JOB_LOG="$3"


SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

export PYTHONPATH="$PYTHONPATH:$SCRIPT_DIR"
export NUMEXPR_MAX_THREADS="$(nproc --all)"

. "$SCRIPT_DIR/enable.sh" "/usr/WS1/$USER/opt/input-gen-release"
export PATH
export LD_LIBRARY_PATH
export LIBRARY_PATH

#NUM_CPU="$(nproc --all)"
NUM_CPU=40

RAY_OUT=$(ray start --head --num-cpus="$NUM_CPU")

IP_ADDR="$(echo $RAY_OUT | grep -o -- "ray start --address='.*'" | grep -o -- '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*:[0-9]*')"

COMMAND="ray start --address=$IP_ADDR --num-cpus=$NUM_CPU --block"
echo $COMMAND

NUM_CHILD_NODES=$(("$NODES" - 1))
flux submit -N "$NUM_CHILD_NODES" -x -t "$TIMEOUT" --output="$JOB_LOG" $COMMAND

while [ "$(ray status  | grep -- ' node_' | wc -l)" != "$NODES" ]; do
    sleep 5s
done

"$SCRIPT_DIR/mass_input_gen.py" \
    --dataset "$(readlink -f /p/vast1/LExperts/ComPile-Public)" \
    --outdir "$(readlink -f "/l/ssd/$USER/compile-input-gen-out/")" \
    --start "$START" \
    --end "$END" \
    --precompile-rts \
    --use-ray \
    --input-gen-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-input-gen.cpp")" \
    --input-run-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-run.cpp")" \
    --input-gen-num 1 \
    --input-gen-num-retries 5 \
    --input-gen-timeout 5 \
    --input-run-timeout 5 \
