#include <algorithm>
#include <bitset>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <sys/resource.h>
#include <type_traits>
#include <vector>

#include "rt.hpp"

namespace {
int VERBOSE = 0;
}

static constexpr intptr_t MinObjAllocation = 64;

template <typename T> static T divFloor(T A, T B) {
  assert(B > 0);
  T Res = A / B;
  T Rem = A % B;
  if (Rem == 0)
    return Res;
  if (Rem < 0) {
    assert(A < 0);
    return Res - 1;
  }
  assert(A > 0);
  return Res;
}

template <typename T> static T divCeil(T A, T B) {
  assert(B > 0);
  T Res = A / B;
  T Rem = A % B;
  if (Rem == 0)
    return Res;
  if (Rem > 0) {
    assert(A > 0);
    return Res + 1;
  }
  assert(A < 0);
  return Res;
}

template <typename T> static T alignStart(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(divFloor(IPtr, Alignment) * Alignment);
}

template <typename T> static T alignEnd(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(divCeil(IPtr, Alignment) * Alignment);
}

static VoidPtrTy advance(VoidPtrTy Ptr, uint64_t Bytes) {
  return reinterpret_cast<uint8_t *>(Ptr) + Bytes;
}

struct ObjectTy {
  const ObjectAddressing &OA;
  ObjectTy(size_t Idx, const ObjectAddressing &OA, VoidPtrTy Output)
      : OA(OA), Idx(Idx) {
    this->Output.Memory = Output;
    this->Output.AllocationSize = OA.MaxObjectSize;
    this->Output.AllocationOffset = OA.getOffsetFromObjBasePtr(nullptr);
  }
  ~ObjectTy() {}

  struct AlignedMemoryChunk {
    VoidPtrTy Ptr;
    intptr_t InputSize;
    intptr_t InputOffset;
    intptr_t OutputSize;
    intptr_t OutputOffset;
  };

  AlignedMemoryChunk getAlignedInputMemory() {
    VoidPtrTy InputStart =
        InputLimits.LowestOffset + Input.Memory - Input.AllocationOffset;
    VoidPtrTy InputEnd =
        InputLimits.HighestOffset + Input.Memory - Input.AllocationOffset;
    intptr_t OutputStart = alignStart(OutputLimits.LowestOffset, ObjAlignment);
    intptr_t OutputEnd = alignEnd(OutputLimits.HighestOffset, ObjAlignment);
    return {InputStart, InputEnd - InputStart, InputLimits.LowestOffset,
            OutputEnd - OutputStart, OutputStart};
  }

  template <typename T> T read(VoidPtrTy Ptr, uint32_t Size);

  template <typename T> void write(T Val, VoidPtrTy Ptr, uint32_t Size) {
    intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
    assert(Output.isAllocated(Offset, Size));
    Used.ensureAllocation(Offset, Size);
    markUsed(Offset, Size);
    OutputLimits.update(Offset, Size);
  }

  const size_t Idx;
  std::set<intptr_t> Ptrs;

private:
  struct Memory {
    VoidPtrTy Memory = nullptr;
    intptr_t AllocationSize = 0;
    intptr_t AllocationOffset = 0;
    bool isAllocated(intptr_t Offset, uint32_t Size) {
      intptr_t AllocatedMemoryStartOffset = AllocationOffset;
      intptr_t AllocatedMemoryEndOffset =
          AllocatedMemoryStartOffset + AllocationSize;
      return (AllocatedMemoryStartOffset <= Offset &&
              AllocatedMemoryEndOffset > Offset + Size);
    }

    /// Returns true if it was already allocated
    bool ensureAllocation(intptr_t Offset, uint32_t Size) {
      if (isAllocated(Offset, Size))
        return true;
      reallocateData(Offset, Size);
      return false;
    }

    template <typename T>
    void extendMemory(T *&OldMemory, intptr_t NewAllocationSize,
                      intptr_t NewAllocationOffset) {
      T *NewMemory = reinterpret_cast<T *>(calloc(NewAllocationSize, 1));
      memcpy(advance(NewMemory, AllocationOffset - NewAllocationOffset),
             OldMemory, AllocationSize);
      free(OldMemory);
      OldMemory = NewMemory;
    };

    /// Reallocates the data so as to make the memory at `Offset` with length
    /// `Size` available
    void reallocateData(intptr_t Offset, uint32_t Size) {
      assert(!isAllocated(Offset, Size));

      intptr_t AllocatedMemoryStartOffset = AllocationOffset;
      intptr_t AllocatedMemoryEndOffset =
          AllocatedMemoryStartOffset + AllocationSize;
      intptr_t NewAllocatedMemoryStartOffset = AllocatedMemoryStartOffset;
      intptr_t NewAllocatedMemoryEndOffset = AllocatedMemoryEndOffset;

      intptr_t AccessStartOffset = Offset;
      intptr_t AccessEndOffset = AccessStartOffset + Size;

      if (AccessStartOffset < AllocatedMemoryStartOffset) {
        // Extend the allocation in the negative direction
        NewAllocatedMemoryStartOffset = alignStart(
            std::min(2 * AccessStartOffset, -MinObjAllocation), ObjAlignment);
      }
      if (AccessEndOffset >= AllocatedMemoryEndOffset) {
        // Extend the allocation in the positive direction
        NewAllocatedMemoryEndOffset = alignEnd(
            std::max(2 * AccessEndOffset, MinObjAllocation), ObjAlignment);
      }

      intptr_t NewAllocationOffset = NewAllocatedMemoryStartOffset;
      intptr_t NewAllocationSize =
          NewAllocatedMemoryEndOffset - NewAllocatedMemoryStartOffset;

      INPUTGEN_DEBUG(
          printf("Reallocating data in Object for access at %ld with size %d "
                 "from offset "
                 "%ld, size %ld to offset %ld, size %ld.\n",
                 Offset, Size, AllocationOffset, AllocationSize,
                 NewAllocationOffset, NewAllocationSize));

      extendMemory(Memory, NewAllocationSize, NewAllocationOffset);

      AllocationSize = NewAllocationSize;
      AllocationOffset = NewAllocationOffset;
    }
  };
  Memory Output, Input, Used;

  struct Limits {
    bool Initialized = false;
    intptr_t LowestOffset = 0;
    intptr_t HighestOffset = 0;
    void update(intptr_t Offset, uint32_t Size) {
      if (!Initialized) {
        Initialized = true;
        LowestOffset = Offset;
        HighestOffset = Offset + Size;
        return;
      }
      if (LowestOffset > Offset)
        LowestOffset = Offset;
      if (HighestOffset < Offset + Size)
        HighestOffset = Offset + Size;
    }
  };
  Limits InputLimits, OutputLimits;

  bool allUsed(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      if (!Used.isAllocated(Offset + It, 1) ||
          !Used.Memory[Offset + It - Used.AllocationOffset])
        return false;
    return true;
  }

  void markUsed(intptr_t Offset, uint32_t Size) {
    assert(Used.isAllocated(Offset, Size));

    for (unsigned It = 0; It < Size; It++)
      Used.Memory[Offset + It - Used.AllocationOffset] = 1;
  }

  template <typename T>
  void storeGeneratedValue(T Val, intptr_t Offset, uint32_t Size) {
    assert(Size == sizeof(Val));

    // Only assign the bytes that were uninitialized
    uint8_t Bytes[sizeof(Val)];
    memcpy(Bytes, &Val, sizeof(Val));
    for (unsigned It = 0; It < sizeof(Val); It++) {
      if (!allUsed(Offset + It, 1)) {
        VoidPtrTy OutputLoc =
            Output.Memory - Output.AllocationOffset + Offset + It;
        VoidPtrTy InputLoc =
            Input.Memory - Input.AllocationOffset + Offset + It;
        *OutputLoc = Bytes[It];
        *InputLoc = Bytes[It];
        markUsed(Offset + It, 1);
      }
    }

    InputLimits.update(Offset, Size);
    OutputLimits.update(Offset, Size);
  }
};

struct GenValTy {
  uint8_t Content[MaxPrimitiveTypeSize] = {0};
  static_assert(sizeof(Content) == MaxPrimitiveTypeSize);
  int32_t IsPtr;
};

template <typename T> static GenValTy toGenValTy(T A, int32_t IsPtr) {
  GenValTy U;
  static_assert(sizeof(T) <= sizeof(U.Content));
  memcpy(U.Content, &A, sizeof(A));
  U.IsPtr = IsPtr;
  return U;
}

std::vector<int32_t> GetObjects;

struct InputGenRTTy {
  InputGenRTTy(const char *ExecPath, const char *OutputDir,
               const char *FuncIdent, VoidPtrTy StackPtr, int Seed)
      : StackPtr(StackPtr), Seed(Seed), FuncIdent(FuncIdent),
        OutputDir(OutputDir), ExecPath(ExecPath) {
    Gen.seed(Seed);
    GenStub.seed(Seed + 1);
    if (this->FuncIdent != "") {
      this->FuncIdent += ".";
    }

    const struct rlimit Rlimit = {RLIM_INFINITY, RLIM_INFINITY};
    int Err = setrlimit(RLIMIT_AS, &Rlimit);
    if (Err)
      INPUTGEN_DEBUG(printf("Could not set bigger limit on malloc: %s\n",
                            strerror(errno)));

    uintptr_t Size = (uintptr_t)16 /*G*/ * 1024 /*M*/ * 1024 /*K*/ * 1024;
    static_assert(sizeof(Size) >= 8);
    // 3/4 of the address space goes to in-object addressing
    do {
      Size = Size / 2;
      OA.setSize(Size);
    } while (!OutputMem.allocate(Size, OA.MaxObjectSize));
    INPUTGEN_DEBUG(printf("Max obj size: 0x%lx, max obj num: %lu\n",
                          OA.MaxObjectSize, OA.MaxObjectNum));

    OutputObjIdxOffset = OA.globalPtrToObjIdx(OutputMem.AlignedMemory);
  }
  ~InputGenRTTy() { report(); }

  VoidPtrTy StackPtr;
  intptr_t OutputObjIdxOffset;
  int32_t Seed, SeedStub;
  std::string FuncIdent;
  std::string OutputDir;
  std::filesystem::path ExecPath;
  std::mt19937 Gen, GenStub;
  std::uniform_int_distribution<> Rand;
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

  int rand(bool Stub) { return Stub ? Rand(GenStub) : Rand(Gen); }

  size_t getNewObj(uint64_t Size, bool Artifical) {
    size_t Idx = Objects.size();
    Objects.push_back(std::make_unique<ObjectTy>(
        Idx, OA, OutputMem.AlignedMemory + Idx * OA.MaxObjectSize));
    return Idx;
  }

  // Returns nullptr if it is not an object managed by us - a stack pointer or
  // memory allocated by malloc
  ObjectTy *globalPtrToObj(VoidPtrTy GlobalPtr) {
    assert(GlobalPtr);
    size_t Idx = OA.globalPtrToObjIdx(GlobalPtr) - OutputObjIdxOffset;
    bool IsExistingObj = Idx >= 0 && Idx < Objects.size();
    [[maybe_unused]] bool IsOutsideObjMemory = Idx > OA.MaxObjectNum || Idx < 0;
    assert(IsExistingObj || IsOutsideObjMemory);
    if (IsExistingObj) {
      INPUTGEN_DEBUG(std::cerr << "Access: " << (void *)GlobalPtr << " Obj #"
                               << Idx << std::endl);
      return Objects[Idx].get();
    }
    INPUTGEN_DEBUG(std::cerr << "Access to memory not handled by us: "
                             << (void *)GlobalPtr << std::endl);
    return nullptr;
  }

  template <typename T> T getNewArg() {
    T V = getNewValue<T>();
    GenVals.push_back(toGenValTy(V, std::is_pointer<T>::value));
    NumArgs++;
    return V;
  }

  template <typename T> T getNewStub() {
    T V = getNewValue<T>(/*Stub=*/true);
    GenVals.push_back(toGenValTy(V, std::is_pointer<T>::value));
    return V;
  }

  template <typename T> T getNewValue(bool Stub = false, int Max = 10) {
    static_assert(!std::is_pointer<T>::value);
    NumNewValues++;
    T V = rand(Stub) % Max;
    return V;
  }

  template <> VoidPtrTy getNewValue<VoidPtrTy>(bool Stub, int Max) {
    NumNewValues++;
    if (rand(Stub) % 75) {
      size_t ObjIdx = getNewObj(/*ignored currently*/ 1024 * 1024, true);
      VoidPtrTy OutputPtr = OA.localPtrToGlobalPtr(ObjIdx + OutputObjIdxOffset,
                                                   OA.getObjBasePtr());
      INPUTGEN_DEBUG(
          printf("New Obj #%lu at output ptr %p\n", ObjIdx, (void *)OutputPtr));
      return OutputPtr;
    }
    INPUTGEN_DEBUG(printf("New Obj = nullptr\n"));
    return nullptr;
  }

  template <typename T> void write(VoidPtrTy Ptr, T Val, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    if (Obj)
      Obj->write<T>(Val, OA.globalPtrToLocalPtr(Ptr), Size);
  }

  template <typename T> T read(VoidPtrTy Ptr, VoidPtrTy Base, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    if (Obj)
      return Obj->read<T>(OA.globalPtrToLocalPtr(Ptr), Size);
    return *reinterpret_cast<T *>(Ptr);
  }

  void registerGlobal(VoidPtrTy Global, VoidPtrTy *ReplGlobal,
                      int32_t GlobalSize) {
    size_t Idx = getNewObj(GlobalSize, false);
    Globals.push_back(Idx);
    INPUTGEN_DEBUG(printf("Global %p replaced with Obj %zu @ %p\n",
                          (void *)Global, Idx, (void *)ReplGlobal));
    *ReplGlobal =
        OA.localPtrToGlobalPtr(Idx + OutputObjIdxOffset, OA.getObjBasePtr());
  }

  std::vector<size_t> Globals;

  uint64_t NumNewValues = 0;

  std::vector<GenValTy> GenVals;
  uint32_t NumArgs = 0;

  // Storage for dynamic objects, TODO maybe we should introduce a static size
  // object type for when we know the size from static analysis.
  std::vector<std::unique_ptr<ObjectTy>> Objects;

  void report() {
    if (OutputDir == "-") {
      // TODO cross platform
      std::ofstream Null("/dev/null");
      report(Null);
    } else {
      auto FileName = ExecPath.filename().string();
      std::string ReportOutName(OutputDir + "/" + FileName + ".report." +
                                FuncIdent + std::to_string(Seed) + ".txt");
      std::string InputOutName(OutputDir + "/" + FileName + ".input." +
                               FuncIdent + std::to_string(Seed) + ".bin");
      std::ofstream InputOutStream(InputOutName,
                                   std::ios::out | std::ios::binary);
      report(InputOutStream);
    }
  }

  void report(std::ofstream &InputOut) {
    printf("Args (%u total)\n", NumArgs);
    for (size_t I = 0; I < NumArgs; ++I)
      printf("Arg %zu: %p\n", I, (void *)GenVals[I].Content);
    printf("Num new values: %lu\n", NumNewValues);
    // fprintf(ReportOut, "Heap PtrMap: %lu\n", Heap->PtrMap.size());
    // fprintf(ReportOut, "Heap ValMap: %lu\n", Heap->ValMap.size());
    printf("Objects (%zu total)\n", Objects.size());

    writeV<uintptr_t>(InputOut, OA.Size);
    writeV<uintptr_t>(InputOut, OutputObjIdxOffset);
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
      INPUTGEN_DEBUG(
          printf("Obj #%zu aligned memory chunk at %p, input size %lu, input "
                 "offset %ld, output size %lu, output offset %ld\n",
                 Obj->Idx, (void *)MemoryChunk.Ptr, MemoryChunk.InputSize,
                 MemoryChunk.InputOffset, MemoryChunk.OutputSize,
                 MemoryChunk.OutputOffset));
      writeV<intptr_t>(InputOut, I);
      writeV<intptr_t>(InputOut, MemoryChunk.InputSize);
      writeV<intptr_t>(InputOut, MemoryChunk.InputOffset);
      writeV<intptr_t>(InputOut, MemoryChunk.OutputSize);
      writeV<intptr_t>(InputOut, MemoryChunk.OutputOffset);
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
      writeV<uint32_t>(InputOut, Globals[I]);
      INPUTGEN_DEBUG(printf("Glob %u %lu\n", I, Globals[I]));
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
  }
};

static InputGenRTTy *InputGenRT;
#pragma omp threadprivate(InputGenRT)

static InputGenRTTy &getInputGenRT() { return *InputGenRT; }

template <typename T> T ObjectTy::read(VoidPtrTy Ptr, uint32_t Size) {
  intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
  assert(Output.isAllocated(Offset, Size));
  Used.ensureAllocation(Offset, Size);
  Input.ensureAllocation(Offset, Size);

  T *OutputLoc = reinterpret_cast<T *>(
      advance(Output.Memory, -Output.AllocationOffset + Offset));
  if (allUsed(Offset, Size))
    return *OutputLoc;

  T Val = getInputGenRT().getNewValue<T>();
  storeGeneratedValue(Val, Offset, Size);

  if constexpr (std::is_pointer<T>::value)
    Ptrs.insert(Offset);

  return *OutputLoc;
}

extern "C" {
void __inputgen_version_mismatch_check_v1() {}

void __inputgen_init() {
  // getInputGenRT().init();
}
void __inputgen_deinit() {
  // getInputGenRT().init();
}

void __inputgen_global(int32_t NumGlobals, VoidPtrTy Global,
                       VoidPtrTy *ReplGlobal, int32_t GlobalSize) {
  getInputGenRT().registerGlobal(Global, ReplGlobal, GlobalSize);
}

// TODO: need to support overlapping Tgt and Src here
VoidPtrTy __inputgen_memmove(VoidPtrTy Tgt, VoidPtrTy Src, uint64_t N) {
  VoidPtrTy SrcIt = Src;
  VoidPtrTy TgtIt = Tgt;
  for (uintptr_t I = 0; I < N; ++I, ++SrcIt, ++TgtIt) {
    auto V = getInputGenRT().read<char>(SrcIt, Src, sizeof(char));
    getInputGenRT().write<char>(TgtIt, V, sizeof(char));
  }
  return TgtIt;
}
VoidPtrTy __inputgen_memcpy(VoidPtrTy Tgt, VoidPtrTy Src, uint64_t N) {
  return __inputgen_memmove(Tgt, Src, N);
}

VoidPtrTy __inputgen_memset(VoidPtrTy Tgt, char C, uint64_t N) {
  VoidPtrTy TgtIt = Tgt;
  for (uintptr_t I = 0; I < N; ++I, ++TgtIt) {
    getInputGenRT().write<char>(TgtIt, C, sizeof(char));
  }
  return TgtIt;
}

#define RW(TY, NAME)                                                           \
  TY __inputgen_get_##NAME() { return getInputGenRT().getNewStub<TY>(); }      \
  void __inputgen_access_##NAME(VoidPtrTy Ptr, int64_t Val, int32_t Size,      \
                                VoidPtrTy Base, int32_t Kind) {                \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().read<TY>(Ptr, Base, Size);                               \
      return;                                                                  \
    case 1:                                                                    \
      TY TyVal;                                                                \
      /* We need to reinterpret_cast fp types because they are just bitcast    \
         to the int64_t type in LLVM. */                                       \
      if (std::is_same<TY, float>::value) {                                    \
        int32_t Trunc = (int32_t)Val;                                          \
        TyVal = *reinterpret_cast<TY *>(&Trunc);                               \
      } else if (std::is_same<TY, double>::value) {                            \
        TyVal = *reinterpret_cast<TY *>(&Val);                                 \
      } else {                                                                 \
        TyVal = (TY)Val;                                                       \
      }                                                                        \
      getInputGenRT().write<TY>(Ptr, TyVal, Size);                             \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }

#define RWREF(TY, NAME)                                                        \
  TY __inputgen_get_##NAME() { return getInputGenRT().getNewStub<TY>(); }      \
  void __inputgen_access_##NAME(VoidPtrTy Ptr, int64_t Val, int32_t Size,      \
                                VoidPtrTy Base, int32_t Kind) {                \
    static_assert(sizeof(TY) > 8);                                             \
    TY TyVal;                                                                  \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().read<TY>(Ptr, Base, Size);                               \
      return;                                                                  \
    case 1:                                                                    \
      TyVal = *(TY *)Val;                                                      \
      getInputGenRT().write<TY>(Ptr, TyVal, Size);                             \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }

RW(bool, i1)
RW(char, i8)
RW(short, i16)
RW(int32_t, i32)
RW(int64_t, i64)
RW(float, float)
RW(double, double)
RW(VoidPtrTy, ptr)
RWREF(__int128, i128)
RWREF(long double, x86_fp80)
#undef RW

#define ARG(TY, NAME)                                                          \
  TY __inputgen_arg_##NAME() { return getInputGenRT().getNewArg<TY>(); }

ARG(bool, i1)
ARG(char, i8)
ARG(short, i16)
ARG(int32_t, i32)
ARG(int64_t, i64)
ARG(float, float)
ARG(double, double)
ARG(VoidPtrTy, ptr)
ARG(__int128, i128)
ARG(long double, x86_fp80)
#undef ARG

void __inputgen_use(VoidPtrTy Ptr, uint32_t Size) { useValue(Ptr, Size); }
}

int main(int argc, char **argv) {
  VERBOSE = (bool)getenv("VERBOSE");

  uint8_t Tmp;
  VoidPtrTy StackPtr = &Tmp;
  INPUTGEN_DEBUG(std::cerr << "Stack pointer: " << (void *)StackPtr
                           << std::endl);

  if (argc != 7 && argc != 4) {
    std::cerr << "Wrong usage." << std::endl;
    return 1;
  }

  const char *OutputDir = argv[1];
  int Start = std::stoi(argv[2]);
  int End = std::stoi(argv[3]);
  std::string FuncName = ("__inputgen_entry");
  std::string FuncIdent = "";
  if (argc == 7) {
    std::string Type = argv[4];
    FuncName += "___inputgen_renamed_";
    if (Type == "--name") {
      FuncIdent += argv[6];
      FuncName += argv[5];
    } else if (Type == "--file") {
      FuncIdent += argv[6];
      FuncName += getFunctionNameFromFile(argv[5], FuncIdent);
    } else {
      std::cerr << "Invalid arg type, must be --name or --file" << std::endl;
      abort();
    }
  }

  int Size = End - Start;
  if (Size <= 0)
    return 1;

  std::cout << "Will generate " << Size << " inputs for function " << FuncName
            << " " << FuncIdent << std::endl;

  void *Handle = dlopen(NULL, RTLD_NOW);
  if (!Handle) {
    std::cout << "Could not dyn load binary" << std::endl;
    std::cout << dlerror() << std::endl;
    return 11;
  }
  typedef void (*EntryFnType)(int, char **);
  EntryFnType EntryFn = (EntryFnType)dlsym(Handle, FuncName.c_str());

  if (!EntryFn) {
    std::cout << "Function " << FuncName << " not found in binary."
              << std::endl;
    return 12;
  }

  for (int I = Start; I < End; I++) {
    InputGenRTTy LocalInputGenRT(argv[0], OutputDir, FuncIdent.c_str(),
                                 StackPtr, I);
    InputGenRT = &LocalInputGenRT;
    EntryFn(argc, argv);
  }

  dlclose(Handle);

  return 0;
}
