#!/usr/bin/env bash

set -e

module load python/3.10.8

if [ "$SINGLE" != "" ]; then
    START="$SINGLE"
    END="$(("$SINGLE" + 1))"
fi

START=${START:=0}
END=${END:=7000}
NUM_CPU=${NUM_CPU:="$(nproc --all)"}

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

SCRIPT="$SCRIPT_DIR/mass_input_gen.py"

if [ "$JUG" == "run" ]; then
    JUG_RUN="jug-execute --will-cite"
    SCRIPT="$SCRIPT_DIR/jugfile.py"
    DASHDASH=--
elif [ "$JUG" == "status" ]; then
    JUG_RUN="jug status"
    SCRIPT="$SCRIPT_DIR/jugfile.py"
    ADDITIONAL_FLAGS="$ADDITIONAL_FLAGS --get-jug-results"
    DASHDASH=--
elif [ "$JUG" == "results" ]; then
    JUG_RUN=
    SCRIPT="$SCRIPT_DIR/print_mig_jug_results.py"
    ADDITIONAL_FLAGS="$ADDITIONAL_FLAGS --get-jug-results"
elif [ "$JUG" != "" ]; then
    echo Invalid JUG option 1>&2
    exit 1
fi

if [ "$NOCLEANUP" == "" ]; then
    ADDITIONAL_FLAGS="$ADDITIONAL_FLAGS --cleanup"
fi

### Default values. These can be overridden in the user config file below
DATASET="/p/vast1/LExperts/ComPile-Public-V2"
OUTDIR="/l/ssd/$USER/compile-input-gen-out/"
LLVM_INSTALL_DIR="/usr/WS1/$USER/opt/input-gen-release"
### Default values

# User provided configuration
USER_CONFIG="$SCRIPT_DIR/configuration.sh"
if [ -f "$USER_CONFIG" ]; then
    . "$USER_CONFIG"
fi

. "$SCRIPT_DIR/enable.sh" "$LLVM_INSTALL_DIR"
PYTHONPATH="$PYTHONPATH:$SCRIPT_DIR"

function run() {
    $JUG_RUN "$SCRIPT" $DASHDASH \
        --dataset "$DATASET" \
        --outdir "$OUTDIR" \
        --start "$START" \
        --end "$END" \
        --precompile-rts \
        --input-gen-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-input-gen.cpp")" \
        --input-run-runtime "$(readlink -f "$SCRIPT_DIR/../input-gen-runtimes/rt-run.cpp")" \
        --input-gen-num 5 \
        --input-gen-num-retries 5 \
        --input-gen-timeout 5 \
        --input-run-timeout 5 \
        --num-procs="$NUM_CPU" \
        --coverage-statistics \
        --coverage-runtime "$(readlink -f "$LLVM_INSTALL_DIR/lib/clang/19/lib/x86_64-unknown-linux-gnu/libclang_rt.profile.a")" \
        $ADDITIONAL_FLAGS

}
run
