; RUN: rm -rf %t.rundir
; RUN: rm -rf %t.nchannel-basename.*
; RUN: mkdir %t.rundir
; RUN: cp %S/../../../../lib/Analysis/models/log_reader.py %t.rundir
; RUN: cp %S/../../../../lib/Analysis/models/interactive_host.py %t.rundir
; RUN: cp %S/Inputs/interactive_main.py %t.rundir
; RUN: %python %t.rundir/interactive_main.py 3 2.0 %t.nchannel-basename \
; RUN:    opt %S/Inputs/nested.ll -S -O3 --mlgo-loop-unroll-interactive-channel-base=%t.nchannel-basename \
; RUN:    --mlgo-loop-unroll-advisor-mode=development \
; RUN:    --interactive-model-runner-echo-reply \
; RUN:    -debug-only=loop-unroll-development-advisor \
; RUN:    -o /dev/null 2>&1 | FileCheck %s --check-prefix=CHECK1

; RUN: %python %t.rundir/interactive_main.py 3 0.5 %t.nchannel-basename \
; RUN:    opt %S/Inputs/nested.ll -S -O3 --mlgo-loop-unroll-interactive-channel-base=%t.nchannel-basename \
; RUN:    --mlgo-loop-unroll-advisor-mode=development \
; RUN:    --interactive-model-runner-echo-reply \
; RUN:    -debug-only=loop-unroll-development-advisor \
; RUN:    -o /dev/null 2>&1 | FileCheck %s --check-prefix=CHECK2

; CHECK1: mlgo-loop-unroll: got advice factor 5
; CHECK1: mlgo-loop-unroll: unattempted unroll
; CHECK1: mlgo-loop-unroll: got advice factor 5
; CHECK1: mlgo-loop-unroll: unattempted unroll
; CHECK1: mlgo-loop-unroll: got advice factor 5
; CHECK1: mlgo-loop-unroll: unrolled
; CHECK1: mlgo-loop-unroll: got advice factor 5
; CHECK1: mlgo-loop-unroll: unrolled

; CHECK2: mlgo-loop-unroll: got advice nounroll
; CHECK2: mlgo-loop-unroll: unattempted unroll
; CHECK2: mlgo-loop-unroll: got advice nounroll
; CHECK2: mlgo-loop-unroll: unattempted unroll
; CHECK2: mlgo-loop-unroll: got advice nounroll
; CHECK2: mlgo-loop-unroll: unattempted unroll
; CHECK2: mlgo-loop-unroll: got advice nounroll
; CHECK2: mlgo-loop-unroll: unattempted unroll
