; RUN: mkdir -p %t
; RUN: llvm-profdata merge %S/Inputs/profile-usage.proftext -o %t/profile-usage.prof
; RUN: input-gen --verify --output-dir %t --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp --profile-path=%t/profile-usage.prof %s

define i32 @f1() {
  ret i32 0
}
