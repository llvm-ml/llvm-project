; RUN: mkdir -p %t
; RUN: input-gen -g --verify --output-dir %t --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp %s
; RUN: %S/run_all.sh %t
;
; RUN: mkdir -p %t/function-wise/
; RUN: input-gen -g --verify --output-dir %t/function-wise --compile-input-gen-executables --input-gen-runtime %S/../../../../input-gen-runtimes/rt-input-gen.cpp --input-run-runtime %S/../../../../input-gen-runtimes/rt-run.cpp %s -function foo
; RUN: %t/function-wise/input-gen.function.foo.generate.a.out %t/function-wise/ 2 3
; RUN: %t/function-wise/input-gen.function.foo.run.a.out %t/function-wise/input-gen.function.foo.generate.a.out.input.2.bin

source_filename = "linked_list.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

@.str = private unnamed_addr constant [20 x i8] c"Length: %i, sum %i\0A\00", align 1, !dbg !0

define dso_local void @baz(ptr noundef readonly %LL) local_unnamed_addr #0 {
entry:
  ret void
}
define dso_local void @bar(ptr noundef readonly %LL) local_unnamed_addr #0 {
entry:
  tail call void @llvm.dbg.value(metadata ptr %LL, metadata !30, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 0, metadata !31, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 0, metadata !32, metadata !DIExpression()), !dbg !33
  %cmp.not6 = icmp eq ptr %LL, null, !dbg !34
  br i1 %cmp.not6, label %while.end, label %while.body, !dbg !35

while.body:                                       ; preds = %entry, %while.body
  %L.09 = phi i32 [ %add1, %while.body ], [ 0, %entry ]
  %S.08 = phi i32 [ %add, %while.body ], [ 0, %entry ]
  %LL.addr.07 = phi ptr [ %1, %while.body ], [ %LL, %entry ]
  tail call void @llvm.dbg.value(metadata i32 %L.09, metadata !32, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 %S.08, metadata !31, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata ptr %LL.addr.07, metadata !30, metadata !DIExpression()), !dbg !33
  %0 = load i32, ptr %LL.addr.07, align 8, !dbg !36, !tbaa !38
  %add = add nsw i32 %0, %S.08, !dbg !44
  tail call void @llvm.dbg.value(metadata i32 %add, metadata !31, metadata !DIExpression()), !dbg !33
  %add1 = add nuw nsw i32 %L.09, 1, !dbg !45
  tail call void @llvm.dbg.value(metadata i32 %add1, metadata !32, metadata !DIExpression()), !dbg !33
  %Next = getelementptr inbounds i8, ptr %LL.addr.07, i64 8, !dbg !46
  %1 = load ptr, ptr %Next, align 8, !dbg !46, !tbaa !47
  tail call void @llvm.dbg.value(metadata ptr %1, metadata !30, metadata !DIExpression()), !dbg !33
  %cmp.not = icmp eq ptr %1, null, !dbg !34
  br i1 %cmp.not, label %while.end, label %while.body, !dbg !35, !llvm.loop !48

while.end:                                        ; preds = %while.body, %entry
  %S.0.lcssa = phi i32 [ 0, %entry ], [ %add, %while.body ], !dbg !33
  %L.0.lcssa = phi i32 [ 0, %entry ], [ %add1, %while.body ], !dbg !33
  %call = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str, i32 noundef %L.0.lcssa, i32 noundef %S.0.lcssa), !dbg !51
  ret void, !dbg !52
}
; Function Attrs: nofree nounwind uwtable
define dso_local void @foo(ptr noundef readonly %LL) local_unnamed_addr #0 !dbg !26 {
entry:
  tail call void @llvm.dbg.value(metadata ptr %LL, metadata !30, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 0, metadata !31, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 0, metadata !32, metadata !DIExpression()), !dbg !33
  %cmp.not6 = icmp eq ptr %LL, null, !dbg !34
  br i1 %cmp.not6, label %while.end, label %while.body, !dbg !35

while.body:                                       ; preds = %entry, %while.body
  %L.09 = phi i32 [ %add1, %while.body ], [ 0, %entry ]
  %S.08 = phi i32 [ %add, %while.body ], [ 0, %entry ]
  %LL.addr.07 = phi ptr [ %1, %while.body ], [ %LL, %entry ]
  tail call void @llvm.dbg.value(metadata i32 %L.09, metadata !32, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata i32 %S.08, metadata !31, metadata !DIExpression()), !dbg !33
  tail call void @llvm.dbg.value(metadata ptr %LL.addr.07, metadata !30, metadata !DIExpression()), !dbg !33
  %0 = load i32, ptr %LL.addr.07, align 8, !dbg !36, !tbaa !38
  %add = add nsw i32 %0, %S.08, !dbg !44
  tail call void @llvm.dbg.value(metadata i32 %add, metadata !31, metadata !DIExpression()), !dbg !33
  %add1 = add nuw nsw i32 %L.09, 1, !dbg !45
  tail call void @llvm.dbg.value(metadata i32 %add1, metadata !32, metadata !DIExpression()), !dbg !33
  %Next = getelementptr inbounds i8, ptr %LL.addr.07, i64 8, !dbg !46
  %1 = load ptr, ptr %Next, align 8, !dbg !46, !tbaa !47
  tail call void @llvm.dbg.value(metadata ptr %1, metadata !30, metadata !DIExpression()), !dbg !33
  %cmp.not = icmp eq ptr %1, null, !dbg !34
  br i1 %cmp.not, label %while.end, label %while.body, !dbg !35, !llvm.loop !48

while.end:                                        ; preds = %while.body, %entry
  %S.0.lcssa = phi i32 [ 0, %entry ], [ %add, %while.body ], !dbg !33
  %L.0.lcssa = phi i32 [ 0, %entry ], [ %add1, %while.body ], !dbg !33
  %call = tail call i32 (ptr, ...) @printf(ptr noundef nonnull dereferenceable(1) @.str, i32 noundef %L.0.lcssa, i32 noundef %S.0.lcssa), !dbg !51
  ret void, !dbg !52
}

; Function Attrs: nofree nounwind
declare !dbg !53 noundef i32 @printf(ptr nocapture noundef readonly, ...) local_unnamed_addr #1

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.value(metadata, metadata, metadata) #2

attributes #0 = { nofree nounwind uwtable "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nofree nounwind "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!18, !19, !20, !21, !22, !23, !24}
!llvm.ident = !{!25}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 16, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "linked_list.c", directory: "/usr/WS1/ivanov2/src/input-gen/tests", checksumkind: CSK_MD5, checksum: "09ffe220e45e48d6a12674b4c73d32ba")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 160, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 20)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "clang version 19.0.0git (https://github.com/jdoerfert/llvm-project/ 5039792df9b9a22ce8b1418fd73f462a198cb1e4)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !8, globals: !17, splitDebugInlining: false, nameTableKind: None)
!8 = !{!9}
!9 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !10, size: 64)
!10 = !DIDerivedType(tag: DW_TAG_typedef, name: "LinkedList", file: !2, line: 7, baseType: !11)
!11 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "LinkedList", file: !2, line: 4, size: 128, elements: !12)
!12 = !{!13, !15}
!13 = !DIDerivedType(tag: DW_TAG_member, name: "Payload", scope: !11, file: !2, line: 5, baseType: !14, size: 32)
!14 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!15 = !DIDerivedType(tag: DW_TAG_member, name: "Next", scope: !11, file: !2, line: 6, baseType: !16, size: 64, offset: 64)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !11, size: 64)
!17 = !{!0}
!18 = !{i32 7, !"Dwarf Version", i32 5}
!19 = !{i32 2, !"Debug Info Version", i32 3}
!20 = !{i32 1, !"wchar_size", i32 4}
!21 = !{i32 8, !"PIC Level", i32 2}
!22 = !{i32 7, !"PIE Level", i32 2}
!23 = !{i32 7, !"uwtable", i32 2}
!24 = !{i32 7, !"debug-info-assignment-tracking", i1 true}
!25 = !{!"clang version 19.0.0git (https://github.com/jdoerfert/llvm-project/ 5039792df9b9a22ce8b1418fd73f462a198cb1e4)"}
!26 = distinct !DISubprogram(name: "foo", scope: !2, file: !2, line: 9, type: !27, scopeLine: 9, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !7, retainedNodes: !29)
!27 = !DISubroutineType(types: !28)
!28 = !{null, !9}
!29 = !{!30, !31, !32}
!30 = !DILocalVariable(name: "LL", arg: 1, scope: !26, file: !2, line: 9, type: !9)
!31 = !DILocalVariable(name: "S", scope: !26, file: !2, line: 10, type: !14)
!32 = !DILocalVariable(name: "L", scope: !26, file: !2, line: 10, type: !14)
!33 = !DILocation(line: 0, scope: !26)
!34 = !DILocation(line: 11, column: 13, scope: !26)
!35 = !DILocation(line: 11, column: 3, scope: !26)
!36 = !DILocation(line: 12, column: 14, scope: !37)
!37 = distinct !DILexicalBlock(scope: !26, file: !2, line: 11, column: 19)
!38 = !{!39, !40, i64 0}
!39 = !{!"LinkedList", !40, i64 0, !43, i64 8}
!40 = !{!"int", !41, i64 0}
!41 = !{!"omnipotent char", !42, i64 0}
!42 = !{!"Simple C/C++ TBAA"}
!43 = !{!"any pointer", !41, i64 0}
!44 = !DILocation(line: 12, column: 7, scope: !37)
!45 = !DILocation(line: 13, column: 7, scope: !37)
!46 = !DILocation(line: 14, column: 28, scope: !37)
!47 = !{!39, !43, i64 8}
!48 = distinct !{!48, !35, !49, !50}
!49 = !DILocation(line: 15, column: 3, scope: !26)
!50 = !{!"llvm.loop.mustprogress"}
!51 = !DILocation(line: 16, column: 3, scope: !26)
!52 = !DILocation(line: 17, column: 1, scope: !26)
!53 = !DISubprogram(name: "printf", scope: !54, file: !54, line: 332, type: !55, flags: DIFlagPrototyped, spFlags: DISPFlagOptimized)
!54 = !DIFile(filename: "include/stdio.h", directory: "/usr", checksumkind: CSK_MD5, checksum: "75d393d9743f4e6c39653f794c599a10")
!55 = !DISubroutineType(types: !56)
!56 = !{!14, !57, null}
!57 = !DIDerivedType(tag: DW_TAG_restrict_type, baseType: !58)
!58 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !4)
