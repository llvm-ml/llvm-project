; RUN: mkdir -p %t
; RUN: input-gen --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp --instrumented-module-for-coverage --profiling-runtime-path=%libclang_rt_profile %s
; RUN: %S/run_all.sh %t
; RUN: llvm-profdata merge %t/i64.profraw %t/0.profraw -o %t/coverage.prof
; RUN: mbb-pgo-info --bc-path=%s --profile-path=%t/coverage.prof | FileCheck %s

; CHECK: "NumBlocksExecuted": 1

define dso_local i64 @i64(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i64, ptr %LL
  store i64 %a, ptr %LL
  ret i64 %a
}
