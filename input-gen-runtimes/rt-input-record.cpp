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
#include <utility>
#include <vector>

#include "rt-common.hpp"

using BranchHint = llvm::inputgen::BranchHint;

struct InputRecordConfTy {
  InputRecordConfTy() {}
};

struct StaticSizeObjectTy {
  StaticSizeObjectTy(size_t Idx, VoidPtrTy Output, size_t Size) {
    this->Output.Memory = Output;
    this->Output.AllocationSize = Size;
    this->Output.AllocationOffset = 0;
  }
  ObjectTy::Memory Output, Input, Used;
};

struct InputRecordRTTy {

  struct InputRecordObjectAddressing : public ObjectAddressing {
    VoidPtrTy getObjBasePtr() const override { return nullptr; }
    VoidPtrTy getLowestObjPtr() const override { abort(); }
    uintptr_t getMaxObjectSize() const override { abort(); }

    InputRecordRTTy &RT;
    InputRecordObjectAddressing(InputRecordRTTy &RT) : RT(RT) {}
  };
  friend struct InputRecordObjectAddressing;

  InputRecordRTTy(InputRecordConfTy InputGenConf)
      : InputGenConf(InputGenConf), OA(*this) {
    OutputObjIdxOffset = 0;
  }
  ~InputRecordRTTy() {}

  InputRecordConfTy InputGenConf;

  VoidPtrTy StackPtr;
  intptr_t OutputObjIdxOffset;
  std::string FuncIdent;
  std::string OutputDir;
  std::filesystem::path ExecPath;
  std::mt19937 Gen;
  InputRecordObjectAddressing OA;

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
    for (auto &Obj : Objects)
      if (Obj->isGlobalPtrInObject(GlobalPtr))
        return &*Obj;
    return nullptr;
  }
  std::optional<std::pair<ObjectTy *, VoidPtrTy>>
  globalPtrToObjAndLocalPtr(VoidPtrTy GlobalPtr) {
    for (auto &Obj : Objects)
      if (Obj->isGlobalPtrInObject(GlobalPtr))
        return std::make_pair(&*Obj, Obj->getLocalPtr(GlobalPtr));
    return {};
  }

  template <typename T> T generateNewArg(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> void recordArg(T Val) {
    if constexpr (!std::is_same<T, __int128>::value) {
      if constexpr (std::is_pointer<T>::value)
        INPUTGEN_DEBUG(std::cerr << "Recorded arg " << toVoidPtr(Val)
                                 << std::endl);
      else
        INPUTGEN_DEBUG(std::cerr << "Recorded arg " << Val << std::endl);
    }
    GenVals.push_back(toGenValTy(Val, std::is_pointer<T>::value));
  }

  template <typename T>
  T generateNewStubReturn(BranchHint *BHs, int32_t BHSize) {
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
  }

  template <typename T> void write(VoidPtrTy Ptr, T Val, uint32_t Size) {
    if (!Recording)
      return;
    assert(Ptr);
    auto Res = globalPtrToObjAndLocalPtr(Ptr);
    // FIXME need globals and stack handling
    assert(Res);
    auto [Obj, LocalPtr] = *Res;
    INPUTGEN_DEBUG(std::cerr << "write to obj #" << Obj->getIdx() << "\n");
    if (Obj)
      Obj->write<T>(Val, LocalPtr, Size);
  }

  template <typename T>
  void read(VoidPtrTy Ptr, VoidPtrTy Base, uint32_t Size, BranchHint *BHs,
            int32_t BHSize) {
    if (!Recording)
      return;
    assert(Ptr);
    auto Res = globalPtrToObjAndLocalPtr(Ptr);
    // FIXME need globals and stack handling
    assert(Res);
    auto [Obj, LocalPtr] = *Res;
    INPUTGEN_DEBUG(std::cerr << "write to obj #" << Obj->getIdx() << "\n");
    if (Obj)
      Obj->read<T>(LocalPtr, Size, BHs, BHSize);
  }

  void atFree(VoidPtrTy Ptr) {
    INPUTGEN_DEBUG(std::cerr << "Free " << toVoidPtr(Ptr) << std::endl);
  }

  void atMalloc(VoidPtrTy Ptr, size_t Size) {
    INPUTGEN_DEBUG(std::cerr << "Malloc " << toVoidPtr(Ptr) << " Size " << Size
                             << std::endl);
    size_t Idx = Objects.size();
    Objects.push_back(std::make_unique<ObjectTy>(Idx, OA, Ptr, Size));
  }

  void registerGlobal(VoidPtrTy, VoidPtrTy *ReplGlobal, int32_t GlobalSize) {
    std::cerr << "register global not implemented yet\n";
    abort();
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

#if 0
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
#endif

  bool Recording = false;
  void recordPush() {
    if (Recording) {
      std::cerr << "Nested recording! Abort!" << std::endl;
      abort();
    }
    INPUTGEN_DEBUG(std::cout << "Start recording\n");
    Recording = true;
  }
  void recordPop() {
    if (!Recording) {
      std::cerr << "Pop without push? Abort!" << std::endl;
      abort();
    }
    INPUTGEN_DEBUG(std::cout << "Stop recording\n");
    Recording = false;
  }
};

static struct InputRecordRTInit {
  bool Initialized = false;
  std::unique_ptr<InputRecordRTTy> IRRT = nullptr;
  InputRecordRTInit() {
    IRRT.reset(new InputRecordRTTy(InputRecordConfTy()));
    Initialized = true;
  }
} InputRecordRT;
static InputRecordRTTy &getInputRecordRT() { return *InputRecordRT.IRRT; }
static bool &isRTInitialized() { return InputRecordRT.Initialized; }

template <typename T>
void ObjectTy::read(VoidPtrTy Ptr, uint32_t Size, BranchHint *BHs,
                    int32_t BHSize) {
  intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
  assert(Output.isAllocated(Offset, Size));
  Used.ensureAllocation(Offset, Size);
  Input.ensureAllocation(Offset, Size);

  if (allUsed(Offset, Size))
    return;

  T *OutputLoc = reinterpret_cast<T *>(
      advance(Output.Memory, -Output.AllocationOffset + Offset));
  T Val = *OutputLoc;
  // FIXME redundant store - we use the function to mark the correct memory as
  // used, etc
  storeInputValue(Val, Offset, Size);

  if constexpr (std::is_pointer<T>::value)
    Ptrs.insert(Offset);
}

void *malloc(size_t Size) {
  void *(*RealMalloc)(size_t) =
      reinterpret_cast<decltype(RealMalloc)>(dlsym(RTLD_NEXT, "malloc"));
  void *Mem = RealMalloc(Size);
  if (isRTInitialized())
    getInputRecordRT().atMalloc(reinterpret_cast<VoidPtrTy>(Mem), Size);
  return Mem;
}

void free(void *Ptr) {
  void (*RealFree)(void *) =
      reinterpret_cast<decltype(RealFree)>(dlsym(RTLD_NEXT, "free"));
  assert(isRTInitialized());
  getInputRecordRT().atFree(reinterpret_cast<VoidPtrTy>(Ptr));
  RealFree(Ptr);
}

extern "C" {
void __record_push() { getInputRecordRT().recordPush(); }
void __record_pop() { getInputRecordRT().recordPop(); }
}

#define __IG_OBJ__ getInputRecordRT()
#include "rt-common-interface.def"
extern "C" {
DEFINE_INTERFACE(record)
}
