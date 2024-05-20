; RUN: mkdir -p %t
; RUN: input-gen -g --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp %s
; RUN: INPUT_GEN_PTR_CMP_RETRY=1 %S/run_all.sh %t

; ModuleID = 'iterators.cpp'
source_filename = "iterators.cpp"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-redhat-linux-gnu"

@.str = private unnamed_addr constant [7 x i8] c"El %d\0A\00", align 1
@.str.1 = private unnamed_addr constant [8 x i8] c"El1 %d\0A\00", align 1
@.str.2 = private unnamed_addr constant [8 x i8] c"Sum %d\0A\00", align 1

; Function Attrs: nofree norecurse nosync nounwind memory(read, inaccessiblemem: none) uwtable
define dso_local i32 @iterators(ptr noundef readonly %0, ptr noundef readnone %1) local_unnamed_addr #0 {
  %3 = icmp eq ptr %0, %1
  br i1 %3, label %11, label %4

4:                                                ; preds = %2, %4
  %5 = phi i32 [ %9, %4 ], [ 0, %2 ]
  %6 = phi ptr [ %7, %4 ], [ %0, %2 ]
  %7 = getelementptr inbounds i32, ptr %6, i64 1
  %8 = load i32, ptr %6, align 4, !tbaa !3
  %9 = add nsw i32 %8, %5
  %10 = icmp eq ptr %7, %1
  br i1 %10, label %11, label %4, !llvm.loop !7

11:                                               ; preds = %4, %2
  %12 = phi i32 [ 0, %2 ], [ %9, %4 ]
  ret i32 %12
}

; Function Attrs: nofree nounwind uwtable
define dso_local i32 @iterators_print(ptr noundef readonly %0, ptr noundef readnone %1, ptr noundef readonly %2, ptr noundef readnone %3) local_unnamed_addr #1 {
  %5 = icmp eq ptr %0, %1
  br i1 %5, label %6, label %9

6:                                                ; preds = %9, %4
  %7 = phi i32 [ 0, %4 ], [ %14, %9 ]
  %8 = icmp eq ptr %2, %3
  br i1 %8, label %25, label %17

9:                                                ; preds = %4, %9
  %10 = phi ptr [ %12, %9 ], [ %0, %4 ]
  %11 = phi i32 [ %14, %9 ], [ 0, %4 ]
  %12 = getelementptr inbounds i32, ptr %10, i64 1
  %13 = load i32, ptr %10, align 4, !tbaa !3
  %14 = add nsw i32 %13, %11
  %15 = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str, i32 noundef %13)
  %16 = icmp eq ptr %12, %1
  br i1 %16, label %6, label %9, !llvm.loop !10

17:                                               ; preds = %6, %17
  %18 = phi ptr [ %20, %17 ], [ %2, %6 ]
  %19 = phi i32 [ %22, %17 ], [ %7, %6 ]
  %20 = getelementptr inbounds i32, ptr %18, i64 1
  %21 = load i32, ptr %18, align 4, !tbaa !3
  %22 = add nsw i32 %21, %19
  %23 = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str.1, i32 noundef %21)
  %24 = icmp eq ptr %20, %3
  br i1 %24, label %25, label %17, !llvm.loop !11

25:                                               ; preds = %17, %6
  %26 = phi i32 [ %7, %6 ], [ %22, %17 ]
  %27 = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str.2, i32 noundef %26)
  ret i32 %26
}

; Function Attrs: nofree nounwind
declare dso_local noundef i32 @printf(ptr nocapture noundef readonly, ...) local_unnamed_addr #2

attributes #0 = { nofree norecurse nosync nounwind memory(read, inaccessiblemem: none) uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nounwind uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nofree nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1}
!llvm.ident = !{!2}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 7, !"uwtable", i32 2}
!2 = !{!"clang version 16.0.6 (Red Hat 16.0.6-2.module+el8.9.0+19521+190d7aba)"}
!3 = !{!4, !4, i64 0}
!4 = !{!"int", !5, i64 0}
!5 = !{!"omnipotent char", !6, i64 0}
!6 = !{!"Simple C/C++ TBAA"}
!7 = distinct !{!7, !8, !9}
!8 = !{!"llvm.loop.mustprogress"}
!9 = !{!"llvm.loop.unroll.disable"}
!10 = distinct !{!10, !8, !9}
!11 = distinct !{!11, !8, !9}
