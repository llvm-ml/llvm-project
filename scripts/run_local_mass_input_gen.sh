#!/usr/bin/env bash

set -e
set -x

module load python/3.10.8

START=0
END=7000

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CURDATE=$(date +"%Y-%m-%dT%H:%M:%S%z")
JOB_LOG_DIR="$LCWS/results/jobs/$CURDATE/"
mkdir -p "$JOB_LOG_DIR"
JOB_NAME="compile-inputgen"
JOB_LOG="$JOB_LOG_DIR/job-$JOB_NAME.main.out"

echo tail -f "$JOB_LOG"


SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

export PYTHONPATH="$PYTHONPATH:$SCRIPT_DIR"

. "$SCRIPT_DIR/enable.sh" "/usr/WS1/$USER/opt/input-gen-release"
export PATH
export LD_LIBRARY_PATH
export LIBRARY_PATH

#NUM_CPU="$(nproc --all)"
NUM_CPU=40

"$SCRIPT_DIR/mass_input_gen.py" \
    --dataset "/p/vast1/LExperts/ComPile-Public" \
    --outdir "/l/ssd/$USER/compile-input-gen-out/" \
    --start "$START" \
    --end "$END" \
    --precompile-rts \
    --input-gen-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-input-gen.cpp")" \
    --input-run-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-run.cpp")" \
    --input-gen-num 1 \
    --input-gen-num-retries 5 \
    --input-gen-timeout 5 \
    --input-run-timeout 5 \
    --num-procs="$NUM_CPU" &> "$JOB_LOG"
