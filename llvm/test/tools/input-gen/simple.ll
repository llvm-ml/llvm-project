; RUN: mkdir -p %t
; RUN: input-gen -g --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp %s
; RUN: %S/run_all.sh %t

define dso_local float @float(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load float, ptr %LL
  store float %a, ptr %LL
  ret float %a
}

define dso_local double @double(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load double, ptr %LL
  store double %a, ptr %LL
  ret double %a
}

define dso_local x86_fp80 @x86_fp80(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load x86_fp80, ptr %LL
  store x86_fp80 %a, ptr %LL
  ret x86_fp80 %a
}

define dso_local ptr @ptr(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load ptr, ptr %LL
  store ptr %a, ptr %LL
  ret ptr %a
}

define dso_local i128 @i128(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i128, ptr %LL
  store i128 %a, ptr %LL
  ret i128 %a
}

define dso_local i64 @i64(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i64, ptr %LL
  store i64 %a, ptr %LL
  ret i64 %a
}

define dso_local i32 @i32(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i32, ptr %LL
  store i32 %a, ptr %LL
  ret i32 %a
}

define dso_local i16 @i16(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i16, ptr %LL
  store i16 %a, ptr %LL
  ret i16 %a
}

define dso_local i8 @i8(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i8, ptr %LL
  store i8 %a, ptr %LL
  ret i8 %a
}

define dso_local i1 @i1(ptr noundef %LL) local_unnamed_addr #0 {
entry:
  %a = load i1, ptr %LL
  store i1 %a, ptr %LL
  ret i1 %a
}

define dso_local i1 @i1_a(i1 %LL) local_unnamed_addr #0 {
entry:
  ret i1 %LL
}

define dso_local i8 @i8_a(i8 %LL) local_unnamed_addr #0 {
entry:
  ret i8 %LL
}

define dso_local i16 @i16_a(i16 %LL) local_unnamed_addr #0 {
entry:
  ret i16 %LL
}

define dso_local i32 @i32_a(i32 %LL) local_unnamed_addr #0 {
entry:
  ret i32 %LL
}

define dso_local i64 @i64_a(i64 %LL) local_unnamed_addr #0 {
entry:
  ret i64 %LL
}

define dso_local i128 @i128_a(i128 %LL) local_unnamed_addr #0 {
entry:
  ret i128 %LL
}

define dso_local float @float_a(float %LL) local_unnamed_addr #0 {
entry:
  ret float %LL
}

define dso_local double @double_a(double %LL) local_unnamed_addr #0 {
entry:
  ret double %LL
}

define dso_local x86_fp80 @x86_fp80_a(x86_fp80 %LL) local_unnamed_addr #0 {
entry:
  ret x86_fp80 %LL
}

define dso_local ptr @ptr_a(ptr %LL) local_unnamed_addr #0 {
entry:
  ret ptr %LL
}
