; RUN: mkdir -p %t
; RUN: input-gen -g --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp %s
; RUN: %S/run_all.sh %t
; ModuleID = '/l/ssd/ivanov2/compile-input-gen-out/6/mod.bc'
source_filename = "/local-ssd/xnnpack-r7msi2beibvbxa3e6lvblom7qlyd5i24-build/aidengro/spack-stage-xnnpack-2022-02-16-r7msi2beibvbxa3e6lvblom7qlyd5i24/spack-src/src/qs8-vaddc/gen/minmax-avx-mul16-ld64-x32.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%struct.A = type { ptr, i32, float }
; Function Attrs: alwaysinline nounwind uwtable
declare hidden %struct.B @struct()

%struct.B = type { ptr, {i32, {float}, i8} }
; Function Attrs: alwaysinline nounwind uwtable
define hidden %struct.B @nested_struct() #0 {
entry:
  %a = call %struct.B @struct()
  ret %struct.B %a
}

attributes #0 = { alwaysinline nounwind uwtable "min-legal-vector-width"="128" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+avx,+cmov,+crc32,+cx8,+fxsr,+mmx,+popcnt,+sse,+sse2,+sse3,+sse4.1,+sse4.2,+ssse3,+x87,+xsave" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3}
!llvm.ident = !{!4}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{!"clang version 18.0.0 (https://github.com/llvm-ml/llvm-project b452eb491a2ae09c12cc88b715f003377cec543b)"}
!5 = !{!6, !6, i64 0}
!6 = !{!"omnipotent char", !7, i64 0}
!7 = !{!"Simple C/C++ TBAA"}
