#ifndef _INPUT_GEN_RUNTIMES_RT_DUMP_INPUT_H_
#define _INPUT_GEN_RUNTIMES_RT_DUMP_INPUT_H_

template <typename RTTy>
static void dumpInput(std::ofstream &InputOut, RTTy &RT) {
  INPUTGEN_DEBUG({
    fprintf(stderr, "Args (%u total)\n", RT.NumArgs);
    for (size_t I = 0; I < RT.NumArgs; ++I)
      fprintf(stderr, "Arg %zu: %p\n", I, (void *)RT.GenVals[I].Content);
    fprintf(stderr, "Num new values: %lu\n", RT.NumNewValues);
    fprintf(stderr, "Objects (%zu total)\n", RT.Objects.size());
  });

  writeV<uintptr_t>(InputOut, RT.OA.getSize());
  writeV<uintptr_t>(InputOut, RT.OutputObjIdxOffset);
  int32_t SeedStub = 0;
  writeV<uint32_t>(InputOut, SeedStub);

  auto BeforeTotalSize = InputOut.tellp();
  uint64_t TotalSize = 0;
  writeV(InputOut, TotalSize);

  uint32_t NumObjects = RT.Objects.size();
  writeV(InputOut, NumObjects);
  INPUTGEN_DEBUG(fprintf(stderr, "Num Obj %u\n", NumObjects));

  IRVector<ObjectTy::AlignedMemoryChunk> MemoryChunks;
  uintptr_t I = 0;
  for (auto &Obj : RT.Objects) {
    auto MemoryChunk = Obj->getAlignedInputMemory();
    INPUTGEN_DEBUG(fprintf(
        stderr,
        "Obj #%zu aligned memory chunk at %p, input size %lu "
        "offset %ld, output size %lu offset %ld, cmp size %lu offset %ld\n",
        Obj->Idx, (void *)MemoryChunk.Ptr, MemoryChunk.InputSize,
        MemoryChunk.InputOffset, MemoryChunk.OutputSize,
        MemoryChunk.OutputOffset, MemoryChunk.CmpSize, MemoryChunk.CmpOffset));
    writeV<intptr_t>(InputOut, I);
    writeV<intptr_t>(InputOut, MemoryChunk.InputSize);
    writeV<intptr_t>(InputOut, MemoryChunk.InputOffset);
    writeV<intptr_t>(InputOut, MemoryChunk.OutputSize);
    writeV<intptr_t>(InputOut, MemoryChunk.OutputOffset);
    writeV<intptr_t>(InputOut, MemoryChunk.CmpSize);
    writeV<intptr_t>(InputOut, MemoryChunk.CmpOffset);
    InputOut.write(reinterpret_cast<char *>(MemoryChunk.Ptr),
                   MemoryChunk.InputSize);
    TotalSize += MemoryChunk.OutputSize;
    MemoryChunks.push_back(MemoryChunk);

    assert(Obj->Idx == I);
    I++;
  }

  INPUTGEN_DEBUG(fprintf(stderr, "TotalSize %lu\n", TotalSize));
  auto BeforeNumGlobals = InputOut.tellp();
  InputOut.seekp(BeforeTotalSize);
  writeV(InputOut, TotalSize);
  InputOut.seekp(BeforeNumGlobals);

  uint32_t NumGlobals = RT.Globals.size();
  writeV(InputOut, NumGlobals);
  INPUTGEN_DEBUG(fprintf(stderr, "Num Glob %u\n", NumGlobals));

  for (uint32_t I = 0; I < NumGlobals; ++I) {
    auto InputMem =
        RT.Objects[RT.Globals[I].ObjIdx]->getKnownSizeObjectInputMemory(
            RT.OA.globalPtrToLocalPtr(RT.Globals[I].Ptr), RT.Globals[I].Size);
    VoidPtrTy InputStart = RT.OA.localPtrToGlobalPtr(
        RT.Globals[I].ObjIdx + RT.OutputObjIdxOffset, InputMem.Start);
    writeV<VoidPtrTy>(InputOut, RT.Globals[I].Ptr);
    writeV<VoidPtrTy>(InputOut, InputStart);
    writeV<uintptr_t>(InputOut, InputMem.Size);
    INPUTGEN_DEBUG(fprintf(stderr,
                           "Glob %u %p in Obj #%zu input start %p size %zu\n",
                           I, (void *)RT.Globals[I].Ptr, RT.Globals[I].ObjIdx,
                           (void *)InputStart, InputMem.Size));
  }

  I = 0;
  for (auto &Obj : RT.Objects) {
    writeV<intptr_t>(InputOut, Obj->Idx);
    writeV<uintptr_t>(InputOut, Obj->Ptrs.size());
    INPUTGEN_DEBUG(
        fprintf(stderr, "O #%ld NP %ld\n", Obj->Idx, Obj->Ptrs.size()));
    for (auto Ptr : Obj->Ptrs) {
      writeV<intptr_t>(InputOut, Ptr);
      INPUTGEN_DEBUG(fprintf(stderr, "P at %ld : %p\n", Ptr,
                             *reinterpret_cast<void **>(
                                 MemoryChunks[Obj->Idx].Ptr +
                                 MemoryChunks[Obj->Idx].InputOffset + Ptr)));
    }

    writeV<uintptr_t>(InputOut, Obj->FPtrs.size());
    INPUTGEN_DEBUG(
        fprintf(stderr, "O #%ld NFP %ld\n", Obj->Idx, Obj->FPtrs.size()));
    for (auto Ptr : Obj->FPtrs) {
      writeV<intptr_t>(InputOut, Ptr.first);
      writeV<uint32_t>(InputOut, Ptr.second);
      INPUTGEN_DEBUG(
          fprintf(stderr, "FP at %ld : %u\n", Ptr.first, Ptr.second));
    }

    assert(Obj->Idx == I);
    I++;
  }

  uint32_t NumGenVals = RT.GenVals.size();
  INPUTGEN_DEBUG(fprintf(stderr, "Num GenVals %u\n", NumGenVals));
  INPUTGEN_DEBUG(fprintf(stderr, "Num Args %u\n", RT.NumArgs));
  writeV<uint32_t>(InputOut, NumGenVals);
  writeV<uint32_t>(InputOut, RT.NumArgs);
  I = 0;
  for (auto &GenVal : RT.GenVals) {
    INPUTGEN_DEBUG(fprintf(stderr, "GenVal #%ld isPtr %d\n", I, GenVal.IsPtr));
    INPUTGEN_DEBUG(fprintf(stderr, "Content "));
    std::ios_base::fmtflags FF(std::cerr.flags());
    std::cerr << std::hex << std::setfill('0') << std::setw(2);
    for (unsigned J = 0; J < sizeof(GenVal.Content); J++)
      std::cerr << std::setw(2) << (int)GenVal.Content[J] << " ";
    std::cerr.flags(FF);
    INPUTGEN_DEBUG(fprintf(stderr, "\n"));
    static_assert(sizeof(GenVal.Content) == MaxPrimitiveTypeSize);
    InputOut.write(ccast(GenVal.Content), MaxPrimitiveTypeSize);
    writeV<int32_t>(InputOut, GenVal.IsPtr);
  }

  uint32_t NumGenFunctionPtrs = RT.FunctionPtrs.size();
  writeV<uint32_t>(InputOut, NumGenFunctionPtrs);
  for (intptr_t FPOffset : RT.FunctionPtrs) {
    writeV<intptr_t>(InputOut, FPOffset);
  }
}

#endif
