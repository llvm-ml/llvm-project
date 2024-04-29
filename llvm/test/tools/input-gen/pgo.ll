; RUN: mkdir -p %t
; RUN: input-gen --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp --pgo-instr-generate %s
; RUN: %t/input-gen.module.generate.a.out %t 0 1 i64
; RUN: %t/input-gen.module.run.a.out %t/input-gen.module.generate.a.out.input.i64.0.bin i64
; RUN: llvm-profdata merge default.profraw -o %t/default.profdata
; RUN: mkdir -p %t.withpgo
; RUN: input-gen --verify --output-dir %t.withpgo --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp --pgo-instr-use %t/default.profdata %s

define dso_local i64 @i64(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i64, ptr %LL
  store i64 %a, ptr %LL
  ret i64 %a
}
