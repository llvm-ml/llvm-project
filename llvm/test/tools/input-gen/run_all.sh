#!/bin/bash
set -e
set -x

function run() {
  while read -r -d '' func_id; read -r -d '' func_name ; do
    gen="$1/input-gen.module.generate.a.out"
    if [ "$TYPE" == NAME ]; then
      "$gen" "$1" 0 1 --name "$func_name" "$func_id" # 2> "$1/$func_id.gen.err.out" > "$1/$func_id.gen.log.out"
    else
      "$gen" "$1" 0 1 --file "$1/available_functions" "$func_id" # 2> "$1/$func_id.gen.err.out" > "$1/$func_id.gen.log.out"
    fi

    run="$1/input-gen.module.run.a.out"
    for i in "$gen".input."$func_id".*.bin; do
      if [ "$TYPE" == NAME ]; then
        LLVM_PROFILE_FILE=$1/$func_name.profraw "$run" "$i" --name "$func_name" # 2> "$i".run.err.out > "$i".run.log.out
      else
        LLVM_PROFILE_FILE=$1/$func_id.profraw "$run" "$i" --file "$1/available_functions" "$func_id" # 2> "$i".run.err.out > "$i".run.log.out
      fi
    done;
  done < "$1/available_functions"
}

TYPE=NAME run "$1"
TYPE=FILE run "$1"
