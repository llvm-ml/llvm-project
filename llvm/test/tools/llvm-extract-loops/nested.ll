; RUN: mkdir -p %t
; RUN: rm %t/extracted.* || true
; RUN: llvm-extract-loops -S %s --output-prefix %t/extracted. --output-suffix .ll
; RUN: cat %t/extracted.* | FileCheck %s

; CHECK: define{{.*}}@__llvm_extracted_loop
; CHECK: define{{.*}}@__llvm_extracted_loop

define i32 @foo(ptr %array, i32 %length, i32 %n, i32 %l) {
entry:
  %tmp5 = icmp sle i32 %n, 0
  br i1 %tmp5, label %exit, label %outer.loop.preheader

outer.loop.preheader:
  br label %outer.loop

outer.loop:
  %outer.loop.acc = phi i32 [ %outer.loop.acc.next, %outer.loop.inc ], [ 0, %outer.loop.preheader ]
  %i = phi i32 [ %i.next, %outer.loop.inc ], [ 0, %outer.loop.preheader ]
  %tmp6 = icmp sle i32 %l, 0
  br i1 %tmp6, label %outer.loop.inc, label %inner.loop.preheader

inner.loop.preheader:
  br label %inner.loop

inner.loop:
  %inner.loop.acc = phi i32 [ %inner.loop.acc.next, %inner.loop ], [ %outer.loop.acc, %inner.loop.preheader ]
  %j = phi i32 [ %j.next, %inner.loop ], [ 0, %inner.loop.preheader ]

  %within.bounds = icmp ult i32 %j, %length
  call void (i1, ...) @llvm.experimental.guard(i1 %within.bounds, i32 9) [ "deopt"() ]

  %j.i64 = zext i32 %j to i64
  %array.j.ptr = getelementptr inbounds i32, ptr %array, i64 %j.i64
  %array.j = load i32, ptr %array.j.ptr, align 4
  %inner.loop.acc.next = add i32 %inner.loop.acc, %array.j

  %j.next = add nsw i32 %j, 1
  %inner.continue = icmp slt i32 %j.next, %l
  br i1 %inner.continue, label %inner.loop, label %outer.loop.inc

outer.loop.inc:
  %outer.loop.acc.next = phi i32 [ %inner.loop.acc.next, %inner.loop ], [ %outer.loop.acc, %outer.loop ]
  %i.next = add nsw i32 %i, 1
  %outer.continue = icmp slt i32 %i.next, %n
  br i1 %outer.continue, label %outer.loop, label %exit

exit:
  %result = phi i32 [ 0, %entry ], [ %outer.loop.acc.next, %outer.loop.inc ]
  ret i32 %result
}
