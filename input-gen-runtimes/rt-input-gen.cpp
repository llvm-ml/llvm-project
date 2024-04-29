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

static int VERBOSE = 0;

// Must be a power of 2
static constexpr intptr_t MaxObjectSize = 1ULL << 32;

static constexpr intptr_t PtrInObjMask = MaxObjectSize - 1;
static constexpr intptr_t ObjIdxMask = ~(PtrInObjMask);

static void *advance(void *Ptr, uint64_t Bytes) {
  return reinterpret_cast<char *>(Ptr) + Bytes;
}

static intptr_t diff(void *LHS, void *RHS) {
  return reinterpret_cast<char *>(LHS) - reinterpret_cast<char *>(RHS);
}

struct ObjectTy {
  ObjectTy(size_t Idx, bool Artificial = true) : Idx(Idx) {}
  ~ObjectTy() {
    free(Output);
    free(Input);
    free(Used);
  }

  uintptr_t getSize() const { return AllocationSize; }
  void *begin() { return Input; }
  void *end() { return advance(Input, AllocationSize); }
  bool isUsed(void *Ptr, uint32_t Size) {
    return isUsed(diff(Ptr, Input), Size);
  }

  void *getBasePtr() { return reinterpret_cast<void *>(MaxObjectSize / 2); }
  void *getRealPtr(void *Ptr) {
    intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) -
                      reinterpret_cast<intptr_t>(getBasePtr());
    return advance(Output, Offset - AllocationOffset);
  }

  template <typename T> T read(void *Ptr, uint32_t Size);

  template <typename T> void write(T Val, void *Ptr, uint32_t Size) {
    intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) -
                      reinterpret_cast<intptr_t>(getBasePtr());
    ensureAllocation(Offset, Size);
    markUsed(Offset, Size);
  }

  const size_t Idx;

private:
  intptr_t AllocationSize = 0;
  intptr_t AllocationOffset = 0;
  void *Output = nullptr;
  void *Input = nullptr;
  // TODO make this a bit-vector
  uint8_t *Used = nullptr;

  /// Returns true if it was already allocated
  bool ensureAllocation(intptr_t Offset, uint32_t Size) {
    if (isAllocated(Offset, Size))
      return true;
    reallocateData(Offset, Size);
    return false;
  }

  bool isUsed(intptr_t Offset, uint32_t Size) {
    assert(isAllocated(Offset, Size));
    for (unsigned It = 0; It < Size; It++)
      if (!Used[Offset - AllocationOffset])
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
      if (!isUsed(Offset + It, 1)) {
        uint8_t *OutputLoc = reinterpret_cast<uint8_t *>(
            advance(Output, -AllocationOffset + Offset + It));
        uint8_t *InputLoc = reinterpret_cast<uint8_t *>(
            advance(Input, -AllocationOffset + Offset + It));
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
    static constexpr intptr_t MinimumAllocation = 1024;

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
          std::min(2 * AccessStartOffset, -MinimumAllocation);
    }
    if (AccessEndOffset >= AllocatedMemoryEndOffset) {
      // Extend the allocation in the positive direction
      NewAllocatedMemoryEndOffset =
          std::max(2 * AccessEndOffset, MinimumAllocation);
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
};

template <typename T> static T fromArgTy(ArgTy U) {
  static_assert(sizeof(T) <= sizeof(U));
  T A;
  memcpy(&A, &U.Content, sizeof(A));
  return A;
}

template <typename T> static ArgTy toArgTy(T A, int32_t ObjIdx) {
  ArgTy U;
  static_assert(sizeof(T) <= sizeof(U));
  memcpy(&U.Content, &A, sizeof(A));
  U.ObjIdx = ObjIdx;
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
  std::vector<char> Conds;

  int rand(bool Stub) { return Stub ? Rand(GenStub) : Rand(Gen); }

  size_t getNewObj(uint64_t Size, bool Artifical) {
    size_t Idx = Objects.size();
    Objects.push_back(std::make_unique<ObjectTy>(Idx, /*Artificial=*/true));
    return Idx;
  }

  template <typename T>
  T getNewValue(int32_t *ObjIdx = nullptr, bool Stub = false, int Max = 10) {
    NumNewValues++;
    T V = rand(Stub) % Max;
    return V;
  }

  void *localPtrToGlobalPtr(size_t ObjIdx, void *PtrInObj) {
    return reinterpret_cast<void *>((ObjIdx * MaxObjectSize) |
                                    reinterpret_cast<intptr_t>(PtrInObj));
  }

  ObjectTy *globalPtrToObj(void *GlobalPtr) {
    size_t Idx =
        (reinterpret_cast<intptr_t>(GlobalPtr) & ObjIdxMask) / MaxObjectSize;
    // Idx > 0 because Idx = 0 is the NULL pointer (object).
    assert(Idx > 0 && Idx < Objects.size());
    return Objects[Idx].get();
  }

  void *globalPtrToLocalPtr(void *GlobalPtr) {
    return reinterpret_cast<void *>(reinterpret_cast<intptr_t>(GlobalPtr) &
                                    PtrInObjMask);
  }

  template <> void *getNewValue<void *>(int32_t *ObjIdx, bool Stub, int Max) {
    NumNewValues++;
    if (rand(Stub) % 50) {
      size_t ObjIdx = getNewObj(1024 * 1024, true);
      void *Ptr = localPtrToGlobalPtr(ObjIdx, Objects[ObjIdx]->getBasePtr());
      if (VERBOSE)
        printf("New Obj at ptr %p\n", Ptr);
      return Ptr;
    }
    if (VERBOSE)
      printf("New Obj = nullptr\n");
    return nullptr;
  }

  template <typename T> void write(void *Ptr, T Val, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    Obj->write<T>(Val, globalPtrToLocalPtr(Ptr), Size);
  }

  template <typename T> T read(void *Ptr, void *Base, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    return Obj->read<T>(globalPtrToLocalPtr(Ptr), Size);
  }

  void registerGlobal(void *Global, void **ReplGlobal, int32_t GlobalSize) {
    size_t Idx = getNewObj(GlobalSize, false);
    Globals.push_back(Idx);
    if (VERBOSE)
      printf("Global %p replaced with Obj %zu @ %p\n", Global, Idx,
             (void *)ReplGlobal);
    *ReplGlobal = localPtrToGlobalPtr(Idx, Objects[Idx]->getBasePtr());
  }

  void *translatePtr(void *GlobalPtr) {
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

  template <typename T> const char *ccast(T *Ptr) {
    return reinterpret_cast<const char *>(Ptr);
  }
  template <typename T> T writeSingleEl(std::ofstream &Output, T El) {
    Output.write(ccast(&El), sizeof(El));
    return El;
  }

  void report(FILE *ReportOut, std::ofstream &InputOut) {
    fprintf(ReportOut, "Args (%zu total)\n", Args.size());
    for (size_t I = 0; I < Args.size(); ++I)
      fprintf(ReportOut, "Arg %zu: %p\n", I, (void *)Args[I].Content);
    fprintf(ReportOut, "Num new values: %lu\n", NumNewValues);
    fprintf(ReportOut, "Heap PtrMap: %lu\n", Heap->PtrMap.size());
    fprintf(ReportOut, "Heap ValMap: %lu\n", Heap->ValMap.size());
    fprintf(ReportOut, "Objects (%zu total)\n", Objects.size());

    writeSingleEl(InputOut, SeedStub);

    auto BeforeTotalSize = InputOut.tellp();
    uint64_t TotalSize = 0;
    writeSingleEl(InputOut, TotalSize);

    uint32_t NumObjects = ObjectsBak.size();
    writeSingleEl(InputOut, NumObjects);

    std::map<void *, ObjectTy *> TrimmedObjs;
    std::map<uint64_t, void *> Remap;
    for (auto &It : Objects) {
      auto *ObjLIt = It->begin();
      auto *ObjRIt = It->end();
      if (VERBOSE)
        printf("%p : %p :: %lu\n", ObjLIt, ObjRIt, It->getSize());
      while (ObjRIt != ObjLIt) {
        if (It->isUsed(ObjLIt, 1))
          break;
        ObjLIt = advance(ObjLIt, 1);
      }
      if (VERBOSE)
        printf("%p : %p\n", ObjLIt, ObjRIt);
      while (ObjRIt != ObjLIt) {
        if (It->isUsed(advance(ObjRIt, -1), 1))
          break;
        ObjRIt = advance(ObjRIt, -1);
      }
      uint64_t Size =
          reinterpret_cast<char *>(ObjRIt) - reinterpret_cast<char *>(ObjLIt);
      if (VERBOSE)
        printf("Size %lu\n", Size);

      writeSingleEl(InputOut, It->Idx);
      writeSingleEl(InputOut, TotalSize);

      TotalSize += Size;
      if (ObjLIt != ObjRIt)
        TrimmedObjs[ObjLIt] = It.get();
    }

    if (VERBOSE)
      printf("TotalSize %lu\n", TotalSize);
    auto BeforeNumGlobals = InputOut.tellp();
    InputOut.seekp(BeforeTotalSize);
    writeSingleEl(InputOut, TotalSize);
    InputOut.seekp(BeforeNumGlobals);

    uint32_t NumGlobals = Globals.size();
    writeSingleEl(InputOut, NumGlobals);

    for (uint32_t I = 0; I < NumGlobals; ++I) {
      writeSingleEl(InputOut, (uint32_t)Globals[I]);
    }

    // std::map<void *, std::pair<uintptr_t, uint32_t>> ValMap;
    auto End = TrimmedObjs.end();
    if (TrimmedObjs.empty() && !Heap->ValMap.empty()) {
      printf("Problem, no objects!");
      exit(2);
    }

    uint32_t NumVals = Heap->ValMap.size();
    writeSingleEl(InputOut, NumVals);

    for (auto &ValIt : Heap->ValMap) {
      auto It = TrimmedObjs.upper_bound(ValIt.first);
      if (It == TrimmedObjs.begin()) {
        printf("Problem, it is begin()");
        exit(3);
      }
      --It;
      ptrdiff_t Offset = reinterpret_cast<char *>(ValIt.first) -
                         reinterpret_cast<char *>(It->second->begin());
      assert(Offset >= 0);
      writeSingleEl(InputOut, It->second->Idx);
      writeSingleEl(InputOut, Offset);
      auto PtrIt = Heap->PtrMap.find(ValIt.first);

      // Write the obj idx next if its a pointer or the value
      enum Kind : uint32_t {
        IDX = 0,
        CONTENT = 1,
      };
      uintptr_t Content;
      if (PtrIt != Heap->PtrMap.end()) {
        writeSingleEl(InputOut, /* Enum */ Kind::IDX);
        Content = PtrIt->second;
      } else {
        writeSingleEl(InputOut, /* Enum */ Kind::CONTENT);
        Content = ValIt.second.first;
      }
      if (VERBOSE)
        printf("%lu ---> %lu [%i]\n", Offset, Content,
               (PtrIt == Heap->PtrMap.end()));
      writeSingleEl(InputOut, Content);
      // Write the size
      writeSingleEl(InputOut, ValIt.second.second);
    }

    uint32_t NumArgs = Args.size();
    writeSingleEl(InputOut, NumArgs);
    for (auto &Arg : Args) {
      writeSingleEl(InputOut, Arg.Content);
      writeSingleEl(InputOut, Arg.ObjIdx);
    }

    uint32_t NumGetObjects = GetObjects.size();
    writeSingleEl(InputOut, NumGetObjects);
    for (auto ObjIdx : GetObjects) {
      writeSingleEl(InputOut, ObjIdx);
    }
  }
};

static InputGenRTTy *InputGenRT;
#pragma omp threadprivate(InputGenRT)

static InputGenRTTy &getInputGenRT() { return *InputGenRT; }

template <typename T> T ObjectTy::read(void *Ptr, uint32_t Size) {
  intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) -
                    reinterpret_cast<intptr_t>(getBasePtr());
  bool WasAllocated = ensureAllocation(Offset, Size);

  T *OutputLoc =
      reinterpret_cast<T *>(advance(Output, -AllocationOffset + Offset));
  if (WasAllocated && isUsed(Offset, Size))
    return *OutputLoc;

  T Val = getInputGenRT().getNewValue<T>();
  storeGeneratedValue(Val, Offset, Size);

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

void __inputgen_global(int32_t NumGlobals, void *Global, void **ReplGlobal,
                       int32_t GlobalSize) {
  getInputGenRT().registerGlobal(Global, ReplGlobal, GlobalSize);
}

void *__inputgen_memmove(void *Tgt, void *Src, uint64_t N) {
  char *SrcIt = (char *)Src;
  char *TgtIt = (char *)Tgt;
  for (uintptr_t I = 0; I < N; ++I, ++SrcIt, ++TgtIt) {
    auto V = getInputGenRT().read<char>(SrcIt, Src, sizeof(char));
    getInputGenRT().write<char>(TgtIt, V, sizeof(char));
  }
  return TgtIt;
}
void *__inputgen_memcpy(void *Tgt, void *Src, uint64_t N) {
  return __inputgen_memmove(Tgt, Src, N);
}

void *__inputgen_memset(void *Tgt, char C, uint64_t N) {
  char *TgtIt = (char *)Tgt;
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
  void __inputgen_access_##NAME(void *Ptr, int64_t Val, int32_t Size,          \
                                void *Base, int32_t Kind) {                    \
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
      getInputGenRT().write<TY>((TY *)Ptr, TyVal, Size);                       \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }                                                                            \
  void __record_read_##NAME(void *Ptr, int64_t Val, int32_t Size, void *Base,  \
                            int32_t Kind) {                                    \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().read<TY>(Ptr, Base, Size);                               \
      return;                                                                  \
    case 1:                                                                    \
      getInputGenRT().write<TY>((TY *)Ptr, (TY)Val, Size);                     \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }

#define RWREF(TY, NAME)                                                        \
  void __inputgen_access_##NAME(void *Ptr, int64_t Val, int32_t Size,          \
                                void *Base, int32_t Kind) {                    \
    static_assert(sizeof(TY) > 8);                                             \
    TY TyVal;                                                                  \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().read<TY>(Ptr, Base, Size);                               \
      return;                                                                  \
    case 1:                                                                    \
      TyVal = *(TY *)Val;                                                      \
      getInputGenRT().write<TY>((TY *)Ptr, TyVal, Size);                       \
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
RW(void *, ptr)
RWREF(__int128, i128)
RWREF(long double, x86_fp80)
#undef RW

#define ARG(TY, NAME)                                                          \
  TY __inputgen_arg_##NAME() {                                                 \
    int32_t ObjIdx = -1;                                                       \
    getInputGenRT().Args.push_back(                                            \
        toArgTy<TY>(getInputGenRT().getNewValue<TY>(&ObjIdx), ObjIdx));        \
    return fromArgTy<TY>(getInputGenRT().Args.back());                         \
  }

ARG(bool, i1)
ARG(char, i8)
ARG(short, i16)
ARG(int32_t, i32)
ARG(int64_t, i64)
ARG(float, float)
ARG(double, double)
ARG(void *, ptr)
ARG(__int128, i128)
ARG(long double, x86_fp80)
#undef ARG

void *__inputgen_translate_ptr(void *Ptr) {
  return getInputGenRT().translatePtr(Ptr);
}

void free(void *) {}
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
