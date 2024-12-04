#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sys/resource.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "rt-common.hpp"

using BranchHint = llvm::inputgen::BranchHint;

struct GenValTy {
  uint8_t Content[MaxPrimitiveTypeSize] = {0};
  static_assert(sizeof(Content) == MaxPrimitiveTypeSize);
  int32_t IsPtr;
};

struct InputRecordConfTy {
  InputRecordConfTy() {}
};

struct InputRecordRTTy {
  InputRecordRTTy(const char *ExecPath, const char *OutputDir,
                  const char *FuncIdent, VoidPtrTy StackPtr, int Seed,
                  InputRecordConfTy InputGenConf)
      : InputGenConf(InputGenConf), StackPtr(StackPtr), FuncIdent(FuncIdent),
        OutputDir(OutputDir), ExecPath(ExecPath) {
    OutputObjIdxOffset = OA.globalPtrToObjIdx(OutputMem.AlignedMemory);
  }
  ~InputRecordRTTy() {}

  InputRecordConfTy InputGenConf;

  VoidPtrTy StackPtr;
  intptr_t OutputObjIdxOffset;
  std::string FuncIdent;
  std::string OutputDir;
  std::filesystem::path ExecPath;
  std::mt19937 Gen;
  struct AlignedAllocation {
    VoidPtrTy Memory = nullptr;
    uintptr_t Size = 0;
    uintptr_t Alignment = 0;
    VoidPtrTy AlignedMemory = nullptr;
    uintptr_t AlignedSize = 0;
    bool allocate(uintptr_t S, uintptr_t A) {
      if (Memory)
        free(Memory);
      Size = S + A;
      Memory = (VoidPtrTy)malloc(Size);
      if (Memory) {
        Alignment = A;
        AlignedSize = S;
        AlignedMemory = alignEnd(Memory, A);
        INPUTGEN_DEBUG(printf("Allocated 0x%lx (0x%lx) bytes of 0x%lx-aligned "
                              "memory at start %p.\n",
                              AlignedSize, Size, Alignment,
                              (void *)AlignedMemory));
      } else {
        INPUTGEN_DEBUG(
            printf("Unable to allocate memory with size 0x%lx\n", Size));
      }
      return Memory;
    }
    ~AlignedAllocation() { free(Memory); }
  };
  AlignedAllocation OutputMem;
  ObjectAddressing OA;

  struct GlobalTy {
    VoidPtrTy Ptr;
    size_t ObjIdx;
    uintptr_t Size;
  };
  std::vector<GlobalTy> Globals;
  std::vector<intptr_t> FunctionPtrs;

  uint64_t NumNewValues = 0;

  std::vector<GenValTy> GenVals;
  uint32_t NumArgs = 0;

  // Storage for dynamic objects
  std::vector<std::unique_ptr<ObjectTy>> Objects;
  std::vector<size_t> GlobalBundleObjects;

  int rand() { abort(); }

  struct NewObj {
    size_t Idx;
    VoidPtrTy Ptr;
  };
  static constexpr size_t NullPtrIdx = -1;
  static constexpr uint64_t UnknownSize = -1;
  NewObj getNewPtr(uint64_t Size) { abort(); }

  NewObj getNewGlobal(uint64_t Size) { abort(); }

  size_t getObjIdx(VoidPtrTy GlobalPtr, bool AllowNull = false) { abort(); }

  // Returns nullptr if it is not an object managed by us - a stack pointer or
  // memory allocated by malloc
  ObjectTy *globalPtrToObj(VoidPtrTy GlobalPtr, bool AllowNull = false) {
    abort();
  }

  template <typename T> T getNewArg(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> T getNewStub(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> T getDefaultNewValue() { abort(); }

  template <typename T> T getNewValue(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <>
  VoidPtrTy getNewValue<VoidPtrTy>(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <>
  FunctionPtrTy getNewValue<FunctionPtrTy>(BranchHint *BHs, int32_t BHSize) {
    abort();
    return nullptr;
  }

  template <typename T> void write(VoidPtrTy Ptr, T Val, uint32_t Size) {
    std::cerr << "write!\n";
  }

  template <typename T>
  void read(VoidPtrTy Ptr, VoidPtrTy Base, uint32_t Size, BranchHint *BHs,
            int32_t BHSize) {
    std::cerr << "read!\n";
  }

  void registerGlobal(VoidPtrTy, VoidPtrTy *ReplGlobal, int32_t GlobalSize) {
    auto Global = getNewGlobal(GlobalSize);
    Globals.push_back({Global.Ptr, Global.Idx, (uintptr_t)GlobalSize});
    *ReplGlobal = Global.Ptr;
    INPUTGEN_DEBUG(printf("Global %p replaced with Obj %zu @ %p\n",
                          (void *)ReplGlobal, Global.Idx, (void *)Global.Ptr));
  }

  void registerFunctionPtrAccess(VoidPtrTy Ptr, uint32_t Size,
                                 VoidPtrTy *PotentialFPs, uint64_t N) {
    abort();
  }

  intptr_t registerFunctionPtrIdx(size_t N) { abort(); }

  void report() {
    if (OutputDir == "-") {
      // TODO cross platform
      std::ofstream Null("/dev/null");
      report(Null);
    } else {
      auto FileName = ExecPath.filename().string();
      std::string ReportOutName(OutputDir + "/" + FileName + ".report." +
                                FuncIdent + ".txt");
      std::string InputOutName(OutputDir + "/" + FileName + ".input." +
                               FuncIdent + ".bin");
      std::ofstream InputOutStream(InputOutName,
                                   std::ios::out | std::ios::binary);
      report(InputOutStream);
    }
  }

  void report(std::ofstream &InputOut) {
    INPUTGEN_DEBUG({
      printf("Args (%u total)\n", NumArgs);
      for (size_t I = 0; I < NumArgs; ++I)
        printf("Arg %zu: %p\n", I, (void *)GenVals[I].Content);
      printf("Num new values: %lu\n", NumNewValues);
      printf("Objects (%zu total)\n", Objects.size());
    });

    writeV<uintptr_t>(InputOut, OA.Size);
    writeV<uintptr_t>(InputOut, OutputObjIdxOffset);
    int32_t SeedStub = 0;
    writeV<uint32_t>(InputOut, SeedStub);

    auto BeforeTotalSize = InputOut.tellp();
    uint64_t TotalSize = 0;
    writeV(InputOut, TotalSize);

    uint32_t NumObjects = Objects.size();
    writeV(InputOut, NumObjects);
    INPUTGEN_DEBUG(printf("Num Obj %u\n", NumObjects));

    std::vector<ObjectTy::AlignedMemoryChunk> MemoryChunks;
    uintptr_t I = 0;
    for (auto &Obj : Objects) {
      auto MemoryChunk = Obj->getAlignedInputMemory();
      INPUTGEN_DEBUG(printf(
          "Obj #%zu aligned memory chunk at %p, input size %lu "
          "offset %ld, output size %lu offset %ld, cmp size %lu offset %ld\n",
          Obj->Idx, (void *)MemoryChunk.Ptr, MemoryChunk.InputSize,
          MemoryChunk.InputOffset, MemoryChunk.OutputSize,
          MemoryChunk.OutputOffset, MemoryChunk.CmpSize,
          MemoryChunk.CmpOffset));
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

    INPUTGEN_DEBUG(printf("TotalSize %lu\n", TotalSize));
    auto BeforeNumGlobals = InputOut.tellp();
    InputOut.seekp(BeforeTotalSize);
    writeV(InputOut, TotalSize);
    InputOut.seekp(BeforeNumGlobals);

    uint32_t NumGlobals = Globals.size();
    writeV(InputOut, NumGlobals);
    INPUTGEN_DEBUG(printf("Num Glob %u\n", NumGlobals));

    for (uint32_t I = 0; I < NumGlobals; ++I) {
      auto InputMem = Objects[Globals[I].ObjIdx]->getKnownSizeObjectInputMemory(
          OA.globalPtrToLocalPtr(Globals[I].Ptr), Globals[I].Size);
      VoidPtrTy InputStart = OA.localPtrToGlobalPtr(
          Globals[I].ObjIdx + OutputObjIdxOffset, InputMem.Start);
      writeV<VoidPtrTy>(InputOut, Globals[I].Ptr);
      writeV<VoidPtrTy>(InputOut, InputStart);
      writeV<uintptr_t>(InputOut, InputMem.Size);
      INPUTGEN_DEBUG(printf("Glob %u %p in Obj #%zu input start %p size %zu\n",
                            I, (void *)Globals[I].Ptr, Globals[I].ObjIdx,
                            (void *)InputStart, InputMem.Size));
    }

    I = 0;
    for (auto &Obj : Objects) {
      writeV<intptr_t>(InputOut, Obj->Idx);
      writeV<uintptr_t>(InputOut, Obj->Ptrs.size());
      INPUTGEN_DEBUG(printf("O #%ld NP %ld\n", Obj->Idx, Obj->Ptrs.size()));
      for (auto Ptr : Obj->Ptrs) {
        writeV<intptr_t>(InputOut, Ptr);
        INPUTGEN_DEBUG(printf("P at %ld : %p\n", Ptr,
                              *reinterpret_cast<void **>(
                                  MemoryChunks[Obj->Idx].Ptr +
                                  MemoryChunks[Obj->Idx].InputOffset + Ptr)));
      }

      writeV<uintptr_t>(InputOut, Obj->FPtrs.size());
      INPUTGEN_DEBUG(printf("O #%ld NFP %ld\n", Obj->Idx, Obj->FPtrs.size()));
      for (auto Ptr : Obj->FPtrs) {
        writeV<intptr_t>(InputOut, Ptr.first);
        writeV<uint32_t>(InputOut, Ptr.second);
        INPUTGEN_DEBUG(printf("FP at %ld : %u\n", Ptr.first, Ptr.second));
      }

      assert(Obj->Idx == I);
      I++;
    }

    uint32_t NumGenVals = GenVals.size();
    INPUTGEN_DEBUG(printf("Num GenVals %u\n", NumGenVals));
    INPUTGEN_DEBUG(printf("Num Args %u\n", NumArgs));
    writeV<uint32_t>(InputOut, NumGenVals);
    writeV<uint32_t>(InputOut, NumArgs);
    I = 0;
    for (auto &GenVal : GenVals) {
      INPUTGEN_DEBUG(printf("GenVal #%ld isPtr %d\n", I, GenVal.IsPtr));
      INPUTGEN_DEBUG(printf("Content "));
      for (unsigned J = 0; J < sizeof(GenVal.Content); J++)
        INPUTGEN_DEBUG(printf("%d ", (int)GenVal.Content[J]));
      INPUTGEN_DEBUG(printf("\n"));
      static_assert(sizeof(GenVal.Content) == MaxPrimitiveTypeSize);
      InputOut.write(ccast(GenVal.Content), MaxPrimitiveTypeSize);
      writeV<int32_t>(InputOut, GenVal.IsPtr);
    }

    uint32_t NumGenFunctionPtrs = FunctionPtrs.size();
    writeV<uint32_t>(InputOut, NumGenFunctionPtrs);
    for (intptr_t FPOffset : FunctionPtrs) {
      writeV<intptr_t>(InputOut, FPOffset);
    }
  }
};

static InputRecordRTTy *InputRecordRT;
static InputRecordRTTy &getInputRecordRT() { return *InputRecordRT; }

extern "C" {
void __record_push() { std::cout << "Start recording\n"; }
void __record_pop() { std::cout << "Stop recording\n"; }
}

#define __IG_OBJ__ getInputRecordRT()
#include "interface.def"
extern "C" {
DEFINE_INTERFACE(record)
}
