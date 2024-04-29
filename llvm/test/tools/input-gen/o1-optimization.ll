; RUN: mkdir -p %t
; RUN: input-gen --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp --optimize-before-instrumenting %s
; RUN: %S/run_all.sh %t

define dso_local i64 @i64(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i64, ptr %LL
  store i64 %a, ptr %LL
  ret i64 %a
}
