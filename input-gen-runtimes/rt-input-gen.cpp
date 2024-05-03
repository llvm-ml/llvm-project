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

template <typename T> static T alignStart(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(IPtr / Alignment * Alignment);
}

template <typename T> static T alignEnd(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>((((IPtr - 1) / Alignment) + 1) * Alignment);
}

static VoidPtrTy advance(VoidPtrTy Ptr, uint64_t Bytes) {
  return reinterpret_cast<uint8_t *>(Ptr) + Bytes;
}

static intptr_t diff(VoidPtrTy LHS, VoidPtrTy RHS) {
  return reinterpret_cast<uint8_t *>(LHS) - reinterpret_cast<uint8_t *>(RHS);
}

struct ObjectTy {
  const ObjectAddressing &OA;
  ObjectTy(size_t Idx, const ObjectAddressing &OA, VoidPtrTy Output,
           VoidPtrTy Input, VoidPtrTy Used)
      : OA(OA), Idx(Idx), Output(Output), Input(Input), Used(Used) {
    AllocationSize = OA.MaxObjectSize;
    AllocationOffset = OA.getOffsetFromObjBasePtr(nullptr);
  }
  ~ObjectTy() {}

  struct AlignedMemoryChunk {
    VoidPtrTy Ptr;
    intptr_t Size;
    intptr_t Offset;
  };

  AlignedMemoryChunk getAlignedInputMemory() {
    VoidPtrTy Start =
        alignStart(LowestUsedOffset + Input - AllocationOffset, ObjAlignment);
    VoidPtrTy End =
        alignEnd(HighestUsedOffset + Input - AllocationOffset, ObjAlignment);
    assert(reinterpret_cast<intptr_t>(Start) % ObjAlignment == 0 &&
           reinterpret_cast<intptr_t>(End) % ObjAlignment == 0);
    return {Start, End - Start, Start - (Input - AllocationOffset)};
  }

  template <typename T> T read(VoidPtrTy Ptr, uint32_t Size);

  template <typename T> void write(T Val, VoidPtrTy Ptr, uint32_t Size) {
    intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
    if constexpr (std::is_pointer<T>::value)
      if (!allUsed(Offset, Size))
        Ptrs.insert(Offset);
    markUsed(Offset, Size);
  }

  const size_t Idx;
  std::set<intptr_t> Ptrs;

private:
  intptr_t AllocationSize = 0;
  intptr_t AllocationOffset = 0;
  VoidPtrTy Output = nullptr;
  VoidPtrTy Input = nullptr;
  // TODO make this a bit-vector
  uint8_t *Used = nullptr;

  intptr_t LowestUsedOffset = 0;
  intptr_t HighestUsedOffset = 0;

  bool anyUsed(VoidPtrTy Ptr, uint32_t Size) {
    return anyUsed(diff(Ptr, Input), Size);
  }

  bool anyUsed(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      if (isAllocated(Offset + It, 1) && Used[Offset - AllocationOffset])
        return true;
    return false;
  }

  bool allUsed(VoidPtrTy Ptr, uint32_t Size) {
    return allUsed(diff(Ptr, Input), Size);
  }

  bool allUsed(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      if (!isAllocated(Offset + It, 1) || !Used[Offset - AllocationOffset])
        return false;
    return true;
  }

  void markUsed(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      Used[Offset - AllocationOffset] = 1;

    if (LowestUsedOffset > Offset)
      LowestUsedOffset = Offset;
    if (HighestUsedOffset < Offset + Size)
      HighestUsedOffset = Offset + Size;
  }

  bool isAllocated(intptr_t Offset, uint32_t Size) {
    intptr_t AllocatedMemoryStartOffset = AllocationOffset;
    intptr_t AllocatedMemoryEndOffset =
        AllocatedMemoryStartOffset + AllocationSize;
    return (AllocatedMemoryStartOffset <= Offset &&
            AllocatedMemoryEndOffset > Offset + Size);
  }

  template <typename T>
  void storeGeneratedValue(T Val, intptr_t Offset, uint32_t Size) {
    assert(Size == sizeof(Val));

    // Only assign the bytes that were uninitialized
    uint8_t Bytes[sizeof(Val)];
    memcpy(Bytes, &Val, sizeof(Val));
    for (unsigned It = 0; It < sizeof(Val); It++) {
      if (!allUsed(Offset + It, 1)) {
        VoidPtrTy OutputLoc = Output - AllocationOffset + Offset + It;
        VoidPtrTy InputLoc = Input - AllocationOffset + Offset + It;
        *OutputLoc = Bytes[It];
        *InputLoc = Bytes[It];
        markUsed(Offset + It, 1);
      }
    }
  }
};

struct GenValTy {
  uint8_t Content[MaxPrimitiveTypeSize];
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
    if (Err && VERBOSE)
      printf("Could not set bigger limit on malloc: %s\n", strerror(errno));

    uintptr_t Size = (uintptr_t)16 /*G*/ * 1024 /*M*/ * 1024 /*K*/ * 1024;
    static_assert(sizeof(Size) >= 8);
    // 3/4 of the address space goes to in-object addressing
    do {
      Size = Size / 2;
      OA.setSize(Size);
    } while (!OutputMem.allocate(Size, OA.MaxObjectSize));
    INPUTGEN_DEBUG(printf("Max obj size: 0x%lx, max obj num: %lu\n",
                          OA.MaxObjectSize, OA.MaxObjectNum));

    assert(OutputMem.allocate(Size, OA.MaxObjectSize));
    assert(InputMem.allocate(Size, OA.MaxObjectSize));
    assert(UsedMem.allocate(Size, OA.MaxObjectSize));

    OutputObjIdxOffset = OA.globalPtrToObjIdx(OutputMem.AlignedMemory);
    InputObjIdxOffset = OA.globalPtrToObjIdx(InputMem.AlignedMemory);
  }
  ~InputGenRTTy() { report(); }

  VoidPtrTy StackPtr;
  intptr_t OutputObjIdxOffset;
  intptr_t InputObjIdxOffset;
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
        AlignedMemory = alignStart(Memory, A);
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
  AlignedAllocation OutputMem, InputMem, UsedMem;
  ObjectAddressing OA;

  int rand(bool Stub) { return Stub ? Rand(GenStub) : Rand(Gen); }

  size_t getNewObj(uint64_t Size, bool Artifical) {
    size_t Idx = Objects.size();
    Objects.push_back(std::make_unique<ObjectTy>(
        Idx, OA, OutputMem.AlignedMemory + Idx * OA.MaxObjectSize,
        InputMem.AlignedMemory + Idx * OA.MaxObjectSize,
        UsedMem.AlignedMemory + Idx * OA.MaxObjectSize));
    return Idx;
  }

  // Returns nullptr if it is not an object managed by us - a stack pointer
  ObjectTy *globalPtrToObj(VoidPtrTy GlobalPtr) {
    size_t Idx = OA.globalPtrToObjIdx(GlobalPtr) - OutputObjIdxOffset;
    INPUTGEN_DEBUG(std::cerr << "Access: " << (void *)GlobalPtr << " Obj #"
                             << Idx << std::endl);
    bool IsExistingObj = Idx >= 0 && Idx < Objects.size();
    bool IsOutsideObjMemory = Idx > OA.MaxObjectNum || Idx < 0;
    assert(IsExistingObj || IsOutsideObjMemory);
    if (IsOutsideObjMemory) {
      // This means it is probably a stack pointer. The assert checks one of the
      // bounds - the other one is unchecked TODO?
      assert(StackPtr >= GlobalPtr);
      return nullptr;
    }
    return Objects[Idx].get();
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
      VoidPtrTy InputPtr = OA.localPtrToGlobalPtr(ObjIdx + InputObjIdxOffset,
                                                  OA.getObjBasePtr());
      INPUTGEN_DEBUG(printf("New Obj #%lu at output ptr %p input ptr %p\n",
                            ObjIdx, (void *)OutputPtr, (void *)InputPtr));
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
          printf("Obj #%zu aligned memory chunk at %p, size %lu, offset %lu\n",
                 Obj->Idx, (void *)MemoryChunk.Ptr, MemoryChunk.Size,
                 MemoryChunk.Offset));
      writeV<intptr_t>(InputOut, Obj->Idx);
      writeV<intptr_t>(InputOut, MemoryChunk.Size);
      writeV<intptr_t>(InputOut, MemoryChunk.Offset);
      InputOut.write(reinterpret_cast<char *>(MemoryChunk.Ptr),
                     MemoryChunk.Size);
      TotalSize += MemoryChunk.Size;
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
        INPUTGEN_DEBUG(printf(
            "P at %ld : %p\n", Ptr,
            *reinterpret_cast<void **>(MemoryChunks[Obj->Idx].Ptr +
                                       MemoryChunks[Obj->Idx].Offset + Ptr)));
      }

      assert(Obj->Idx == I);
      I++;
    }

    uint32_t NumGenVals = GenVals.size();
    writeV<uint32_t>(InputOut, NumGenVals);
    writeV<uint32_t>(InputOut, NumArgs);
    for (auto &GenVal : GenVals) {
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
  intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) -
                    reinterpret_cast<intptr_t>(OA.getObjBasePtr());

  T *OutputLoc =
      reinterpret_cast<T *>(advance(Output, -AllocationOffset + Offset));
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

// TODO these currently do not work properly as they are wider than ptr
ARG(__int128, i128)
ARG(long double, x86_fp80)
#undef ARG

// TODO Need to rename this when instrumenting
// void free(void *) {}
}

int main(int argc, char **argv) {
  VERBOSE = (bool)getenv("VERBOSE");

  uint8_t Tmp;
  VoidPtrTy StackPtr = &Tmp;
  INPUTGEN_DEBUG(std::cerr << "Stack pointer: " << (void *)StackPtr
                           << std::endl);

  if (argc != 5 && argc != 4) {
    std::cerr << "Wrong usage." << std::endl;
    return 1;
  }

  const char *OutputDir = argv[1];
  int Start = std::stoi(argv[2]);
  int End = std::stoi(argv[3]);
  std::string FuncName = ("__inputgen_entry");
  std::string FuncIdent = "";
  if (argc == 5) {
    FuncName += "___inputgen_renamed_";
    FuncName += argv[4];
    FuncIdent += argv[4];
  }

  int Size = End - Start;
  if (Size <= 0)
    return 1;

  std::cout << "Will generate " << Size << " inputs." << std::endl;

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
