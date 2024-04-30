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
#include <type_traits>
#include <vector>

#include "rt.hpp"

static int VERBOSE = 0;

template <typename T> static T alignStart(T Ptr) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(IPtr / ObjAlignment * ObjAlignment);
}

template <typename T> static T alignEnd(T Ptr) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<intptr_t>((((IPtr - 1) / ObjAlignment) + 1) *
                                    ObjAlignment);
}

static VoidPtrTy advance(VoidPtrTy Ptr, uint64_t Bytes) {
  return reinterpret_cast<uint8_t *>(Ptr) + Bytes;
}

static intptr_t diff(VoidPtrTy LHS, VoidPtrTy RHS) {
  return reinterpret_cast<uint8_t *>(LHS) - reinterpret_cast<uint8_t *>(RHS);
}

struct ObjectTy {
  ObjectTy(size_t Idx, bool Artificial = true) : Idx(Idx) {}
  ~ObjectTy() {
    free(Output);
    free(Input);
    free(Used);
  }

  struct AlignedMemoryChunk {
    VoidPtrTy Ptr;
    intptr_t Size;
    intptr_t Offset;
  };

  AlignedMemoryChunk getAlignedInputMemory() {
    VoidPtrTy Start = Input;
    VoidPtrTy End = Input + AllocationSize;
    assert(reinterpret_cast<intptr_t>(Start) % ObjAlignment == 0 &&
           reinterpret_cast<intptr_t>(End) % ObjAlignment == 0);
    while (Start != End && !anyUsed(Start, ObjAlignment))
      Start = Start + ObjAlignment;
    while (Start != End && !anyUsed(End - ObjAlignment, ObjAlignment))
      End = End - ObjAlignment;
    return {Start, End - Start, Start - Input};
  }

  VoidPtrTy getRealPtr(VoidPtrTy Ptr) {
    return advance(Output, getOffsetFromObjBasePtr(Ptr) - AllocationOffset);
  }

  template <typename T> T read(VoidPtrTy Ptr, uint32_t Size);

  template <typename T> void write(T Val, VoidPtrTy Ptr, uint32_t Size) {
    intptr_t Offset = getOffsetFromObjBasePtr(Ptr);
    ensureAllocation(Offset, Size);
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

  /// Returns true if it was already allocated
  bool ensureAllocation(intptr_t Offset, uint32_t Size) {
    if (isAllocated(Offset, Size))
      return true;
    reallocateData(Offset, Size);
    return false;
  }

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
      NewAllocatedMemoryStartOffset =
          alignStart(std::min(2 * AccessStartOffset, -MinObjAllocation));
    }
    if (AccessEndOffset >= AllocatedMemoryEndOffset) {
      // Extend the allocation in the positive direction
      NewAllocatedMemoryEndOffset =
          alignEnd(std::max(2 * AccessEndOffset, MinObjAllocation));
    }

    intptr_t NewAllocationOffset = NewAllocatedMemoryStartOffset;
    intptr_t NewAllocationSize =
        NewAllocatedMemoryEndOffset - NewAllocatedMemoryStartOffset;

    if (VERBOSE)
      printf("Reallocating data in Object %zu for access at %ld with size %d "
             "from offset "
             "%ld, size %ld to offset %ld, size %ld.\n",
             Idx, Offset, Size, AllocationOffset, AllocationSize,
             NewAllocationOffset, NewAllocationSize);

    extendMemory(Input, NewAllocationSize, NewAllocationOffset);
    extendMemory(Output, NewAllocationSize, NewAllocationOffset);
    extendMemory(Used, NewAllocationSize, NewAllocationOffset);

    AllocationSize = NewAllocationSize;
    AllocationOffset = NewAllocationOffset;
  }
};

struct ArgTy {
  uintptr_t Content;
  int32_t ObjIdx;
  int32_t IsPtr;
};

template <typename T> static T fromArgTy(ArgTy U) {
  static_assert(sizeof(T) <= sizeof(U));
  T A;
  memcpy(&A, &U.Content, sizeof(A));
  return A;
}

template <typename T> static ArgTy toArgTy(T A, int32_t ObjIdx, int32_t IsPtr) {
  ArgTy U;
  static_assert(sizeof(T) <= sizeof(U));
  memcpy(&U.Content, &A, sizeof(A));
  U.ObjIdx = ObjIdx;
  U.IsPtr = IsPtr;
  return U;
}

std::vector<int32_t> GetObjects;

struct InputGenRTTy {
  InputGenRTTy(const char *ExecPath, const char *OutputDir,
               const char *FuncIdent, int Seed)
      : Seed(Seed), FuncIdent(FuncIdent), OutputDir(OutputDir),
        ExecPath(ExecPath) {
    Gen.seed(Seed);
    SeedStub = rand(false);
    GenStub.seed(SeedStub);
    if (this->FuncIdent != "") {
      this->FuncIdent += ".";
    }
    // NULL object. This guarantees all the remaining objs will have the top
    // bits > 0.
    getNewObj(0, true);
  }
  ~InputGenRTTy() { report(); }

  int32_t Seed, SeedStub;
  std::string FuncIdent;
  std::string OutputDir;
  std::filesystem::path ExecPath;
  std::mt19937 Gen, GenStub;
  std::uniform_int_distribution<> Rand;

  int rand(bool Stub) { return Stub ? Rand(GenStub) : Rand(Gen); }

  size_t getNewObj(uint64_t Size, bool Artifical) {
    size_t Idx = Objects.size();
    Objects.push_back(std::make_unique<ObjectTy>(Idx, /*Artificial=*/true));
    return Idx;
  }

  template <typename T>
  T getNewValue(int32_t *ObjIdx = nullptr, bool Stub = false, int Max = 10) {
    static_assert(!std::is_pointer<T>::value);
    NumNewValues++;
    T V = rand(Stub) % Max;
    return V;
  }

  VoidPtrTy localPtrToGlobalPtr(size_t ObjIdx, VoidPtrTy PtrInObj) {
    return reinterpret_cast<VoidPtrTy>((ObjIdx * MaxObjectSize) |
                                       reinterpret_cast<intptr_t>(PtrInObj));
  }

  ObjectTy *globalPtrToObj(VoidPtrTy GlobalPtr) {
    size_t Idx = globalPtrToObjIdx(GlobalPtr);
    // Idx > 0 because Idx = 0 is the NULL pointer (object).
    assert(Idx > 0 && Idx < Objects.size());
    return Objects[Idx].get();
  }

  template <>
  VoidPtrTy getNewValue<VoidPtrTy>(int32_t *ObjIdx, bool Stub, int Max) {
    NumNewValues++;
    if (rand(Stub) % 50) {
      size_t ObjIdx = getNewObj(1024 * 1024, true);
      VoidPtrTy Ptr = localPtrToGlobalPtr(ObjIdx, getObjBasePtr());
      if (VERBOSE)
        printf("New Obj #%lu at ptr %p\n", ObjIdx, (void *)Ptr);
      return Ptr;
    }
    if (VERBOSE)
      printf("New Obj = nullptr\n");
    return nullptr;
  }

  template <typename T> void write(VoidPtrTy Ptr, T Val, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    Obj->write<T>(Val, globalPtrToLocalPtr(Ptr), Size);
  }

  template <typename T> T read(VoidPtrTy Ptr, VoidPtrTy Base, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    return Obj->read<T>(globalPtrToLocalPtr(Ptr), Size);
  }

  void registerGlobal(VoidPtrTy Global, VoidPtrTy *ReplGlobal,
                      int32_t GlobalSize) {
    size_t Idx = getNewObj(GlobalSize, false);
    Globals.push_back(Idx);
    if (VERBOSE)
      printf("Global %p replaced with Obj %zu @ %p\n", (void *)Global, Idx,
             (void *)ReplGlobal);
    *ReplGlobal = localPtrToGlobalPtr(Idx, getObjBasePtr());
  }

  VoidPtrTy translatePtr(VoidPtrTy GlobalPtr) {
    return globalPtrToObj(GlobalPtr)->getRealPtr(
        globalPtrToLocalPtr(GlobalPtr));
  }

  std::vector<size_t> Globals;

  uint64_t NumNewValues = 0;

  std::vector<ArgTy> Args;

  // Storage for dynamic objects, TODO maybe we should introduce a static size
  // object type for when we know the size from static analysis.
  std::vector<std::unique_ptr<ObjectTy>> Objects;

  void report() {
    if (OutputDir == "-") {
      // TODO cross platform
      std::ofstream Null("/dev/null");
      report(stdout, Null);
    } else {
      auto FileName = ExecPath.filename().string();
      std::string ReportOutName(OutputDir + "/" + FileName + ".report." +
                                FuncIdent + std::to_string(Seed) + ".txt");
      std::string InputOutName(OutputDir + "/" + FileName + ".input." +
                               FuncIdent + std::to_string(Seed) + ".bin");
      std::ofstream InputOutStream(InputOutName,
                                   std::ios::out | std::ios::binary);
      FILE *ReportOutFD = fopen(ReportOutName.c_str(), "w");
      if (!ReportOutFD) {
        fprintf(stderr, "Could not open %s\n", ReportOutName.c_str());
        return;
      }
      report(ReportOutFD, InputOutStream);
      fclose(ReportOutFD);
    }
  }

  void report(FILE *ReportOut, std::ofstream &InputOut) {
    fprintf(ReportOut, "Args (%zu total)\n", Args.size());
    for (size_t I = 0; I < Args.size(); ++I)
      fprintf(ReportOut, "Arg %zu: %p\n", I, (void *)Args[I].Content);
    fprintf(ReportOut, "Num new values: %lu\n", NumNewValues);
    // fprintf(ReportOut, "Heap PtrMap: %lu\n", Heap->PtrMap.size());
    // fprintf(ReportOut, "Heap ValMap: %lu\n", Heap->ValMap.size());
    fprintf(ReportOut, "Objects (%zu total)\n", Objects.size());

    writeV(InputOut, SeedStub);

    auto BeforeTotalSize = InputOut.tellp();
    uint64_t TotalSize = 0;
    writeV(InputOut, TotalSize);

    uint32_t NumObjects = Objects.size();
    writeV(InputOut, NumObjects);

    std::vector<ObjectTy::AlignedMemoryChunk> MemoryChunks;
    uintptr_t I = 0;
    for (auto &Obj : Objects) {
      auto MemoryChunk = Obj->getAlignedInputMemory();
      if (VERBOSE)
        printf("Obj #%zu aligned memory chunk at %p, size %lu\n", Obj->Idx,
               (void *)MemoryChunk.Ptr, MemoryChunk.Size);
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

    if (VERBOSE)
      printf("TotalSize %lu\n", TotalSize);
    auto BeforeNumGlobals = InputOut.tellp();
    InputOut.seekp(BeforeTotalSize);
    writeV(InputOut, TotalSize);
    InputOut.seekp(BeforeNumGlobals);

    uint32_t NumGlobals = Globals.size();
    writeV(InputOut, NumGlobals);

    for (uint32_t I = 0; I < NumGlobals; ++I) {
      writeV<uint32_t>(InputOut, Globals[I]);
    }

    I = 0;
    for (auto &Obj : Objects) {
      writeV<intptr_t>(InputOut, Obj->Idx);
      writeV<uintptr_t>(InputOut, Obj->Ptrs.size());
      if (VERBOSE)
        printf("O #%ld NP %ld\n", Obj->Idx, Obj->Ptrs.size());
      for (auto Ptr : Obj->Ptrs) {
        writeV<intptr_t>(InputOut, Ptr);
        if (VERBOSE)
          printf("P at %ld : %p\n", Ptr,
                 *reinterpret_cast<void **>(MemoryChunks[Obj->Idx].Ptr +
                                            MemoryChunks[Obj->Idx].Offset +
                                            Ptr));
      }

      assert(Obj->Idx == I);
      I++;
    }

    uint32_t NumArgs = Args.size();
    writeV<uint32_t>(InputOut, NumArgs);
    for (auto &Arg : Args) {
      writeV<uintptr_t>(InputOut, Arg.Content);
      writeV<int32_t>(InputOut, Arg.ObjIdx);
      writeV<int32_t>(InputOut, Arg.IsPtr);
    }

    // uint32_t NumGetObjects = GetObjects.size();
    // writeV(InputOut, NumGetObjects);
    // for (auto ObjIdx : GetObjects) {
    //   writeV(InputOut, ObjIdx);
    // }
  }
};

static InputGenRTTy *InputGenRT;
#pragma omp threadprivate(InputGenRT)

static InputGenRTTy &getInputGenRT() { return *InputGenRT; }

template <typename T> T ObjectTy::read(VoidPtrTy Ptr, uint32_t Size) {
  intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) -
                    reinterpret_cast<intptr_t>(getObjBasePtr());
  bool WasAllocated = ensureAllocation(Offset, Size);

  T *OutputLoc =
      reinterpret_cast<T *>(advance(Output, -AllocationOffset + Offset));
  if (WasAllocated && allUsed(Offset, Size))
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
  TY __inputgen_get_##NAME() {                                                 \
    int32_t ObjIdx = -1;                                                       \
    TY V = getInputGenRT().getNewValue<TY>(&ObjIdx, true);                     \
    if constexpr (std::is_pointer<TY>::value)                                  \
      GetObjects.push_back(ObjIdx);                                            \
    return V;                                                                  \
  }                                                                            \
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
  }                                                                            \
  void __record_read_##NAME(VoidPtrTy Ptr, int64_t Val, int32_t Size,          \
                            VoidPtrTy Base, int32_t Kind) {                    \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().read<TY>(Ptr, Base, Size);                               \
      return;                                                                  \
    case 1:                                                                    \
      getInputGenRT().write<TY>(Ptr, (TY)Val, Size);                           \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }

#define RWREF(TY, NAME)                                                        \
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
  TY __inputgen_arg_##NAME() {                                                 \
    int32_t ObjIdx = -1;                                                       \
    getInputGenRT().Args.push_back(                                            \
        toArgTy<TY>(getInputGenRT().getNewValue<TY>(&ObjIdx), ObjIdx,          \
                    std::is_pointer<TY>::value));                              \
    return fromArgTy<TY>(getInputGenRT().Args.back());                         \
  }

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

VoidPtrTy __inputgen_translate_ptr(VoidPtrTy Ptr) {
  return getInputGenRT().translatePtr(Ptr);
}

// TODO Need to rename this when instrumenting
// void free(VoidPtrTy) {}
}

int main(int argc, char **argv) {
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
    FuncName += "_";
    FuncName += argv[4];
    FuncIdent += argv[4];
  }

  VERBOSE = (bool)getenv("VERBOSE");

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
    InputGenRTTy LocalInputGenRT(argv[0], OutputDir, FuncIdent.c_str(), I);
    InputGenRT = &LocalInputGenRT;
    EntryFn(argc, argv);
  }

  dlclose(Handle);

  return 0;
}
