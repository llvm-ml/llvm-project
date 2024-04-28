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

struct ObjectTy {
  ObjectTy(size_t Idx, bool Artificial = true) : Idx(Idx) {}

  uintptr_t getSize() const { return Size; }
  void *begin() { return Data; }
  void *end() { return advance(Data, Size); }
  bool isInitialized(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      if (!Initialized[AllocationOffset + Offset])
        return false;
    return true;
  }
  void *getBasePtr() { return reinterpret_cast<void *>(MaxObjectSize / 2); }
  template <typename T> T read(void *Ptr, uint32_t Size) {
    intptr_t Offset = reinterpret_cast<intptr_t>(Ptr) - reinterpret_cast<intptr_t>(getBasePtr());
    if (isInitialized(Offset, Size)) {
      T *Ptr = reinterpret_cast<T *>(Output[AllocationOffset + Offset]);
      return *Ptr;
    }
    if (!Output) {
    }

    return *reinterpret_cast<T *>(Ptr);
  }

  const size_t Idx;

private:
  uintptr_t Size = 0;
  intptr_t AllocationOffset = 0;
  void *Output = nullptr;
  void *Input = nullptr;
  uint8_t *Initialized = nullptr;

  void reallocateData(uintptr_t NewSize, intptr_t NewAllocationOffset) {
    assert(Size < NewSize);
    void *NewOutput = malloc(NewSize);
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

static constexpr uint64_t HeapSize = 1UL << 32;

struct HeapTy : ObjectTy {
  HeapTy(HeapTy *LastHeap = nullptr)
      : ObjectTy(malloc(HeapSize), HeapSize), LastHeap(LastHeap) {
    if (VERBOSE)
      printf("New heap [%p:%p)\n", begin(), end());
  }
  HeapTy *LastHeap = nullptr;

  std::bitset<(HeapSize / 8)> UsedSet;

  bool isUsed(void *Ptr, int64_t Size) {
    uintptr_t Offset = (uintptr_t)Ptr - (uintptr_t)begin();
    uintptr_t Idx = Offset / 8;
    bool Res = true;
    do {
      Res &= UsedSet[Idx++];
      Size -= 1;
    } while (Size > 0);
    return Res;
  }
  void markUsed(void *Ptr, int64_t Size) {
    uintptr_t Offset = (uintptr_t)Ptr - (uintptr_t)begin();
    uintptr_t Idx = Offset / 8;
    do {
      UsedSet.set(Idx++);
      Size -= 1;
    } while (Size > 0);
  }

  template <typename T> T read(void *Ptr, void *Base, uint32_t Size);

  template <typename T>
  void write(T *Ptr, T Val, uint32_t Size, bool DueToRead = false,
             int32_t ObjIdx = -1) {
    if (begin() <= Ptr && advance(Ptr, Size) < end()) {
      if (isUsed(Ptr, Size))
        return;
      markUsed(Ptr, Size);
      if (DueToRead)
        memcpy(Ptr, &Val, Size);
      if constexpr (std::is_pointer<T>::value) {
        if (DueToRead && ObjIdx != -1)
          PtrMap[Ptr] = ObjIdx;
      }
      ValMap[Ptr] = {(uintptr_t)Val, Size};
    } else if (LastHeap) {
      LastHeap->write(Ptr, Val, Size, DueToRead);
    } else {
      if (VERBOSE)
        printf("Out of bound write at %p\n", (void *)Ptr);
      // exit(1);
    }
  }

  std::map<void *, int32_t> PtrMap;
  std::map<void *, std::pair<uintptr_t, uint32_t>> ValMap;
};

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
    assert(Idx >= 0 && Idx < Objects.size());
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
      return localPtrToGlobalPtr(ObjIdx, Objects[ObjIdx]->getBasePtr());
    } else {
      return nullptr;
    }
  }

  template <typename T> T read(void *Ptr, void *Base, uint32_t Size) {
    ObjectTy *Obj = globalPtrToObj(Ptr);
    return Obj->read<T>(globalPtrToLocalPtr(Ptr));
  }

  void registerGlobal(void *Global, void **ReplGlobal, int32_t GlobalSize) {
    auto *Obj = getNewObj(GlobalSize, false);
    Globals.push_back(Obj);
    if (VERBOSE)
      printf("Global %p replaced with %p @ %p\n", Global, Obj->begin(),
             ReplGlobal);
    *ReplGlobal = Obj->begin();
  }

  std::vector<ObjectTy *> Globals;

  uint64_t NumNewValues = 0;

  std::vector<ArgTy> Args;

  std::set<ObjectTy *> ObjectsBak;
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
    fprintf(ReportOut, "Objects (%zu total)\n", ObjectsBak.size());

    writeSingleEl(InputOut, SeedStub);

    auto BeforeTotalSize = InputOut.tellp();
    uint64_t TotalSize = 0;
    writeSingleEl(InputOut, TotalSize);

    uint32_t NumObjects = ObjectsBak.size();
    writeSingleEl(InputOut, NumObjects);

    std::map<void *, ObjectTy *> TrimmedObjs;
    std::map<uint64_t, void *> Remap;
    for (auto &It : ObjectsBak) {
      auto *ObjLIt = It->begin();
      auto *ObjRIt = It->end();
      if (VERBOSE)
        printf("%p : %p :: %lu\n", ObjLIt, ObjRIt, It->getSize());
      while (ObjRIt != ObjLIt) {
        if (Heap->isUsed(ObjLIt, 1))
          break;
        ObjLIt = advance(ObjLIt, 1);
      }
      if (VERBOSE)
        printf("%p : %p\n", ObjLIt, ObjRIt);
      while (ObjRIt != ObjLIt) {
        if (Heap->isUsed(advance(ObjRIt, -1), 1))
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
        TrimmedObjs[ObjLIt] = It;
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
      writeSingleEl(InputOut, Globals[I]->Idx);
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

template <typename T> T HeapTy::read(void *Ptr, void *Base, uint32_t Size) {
  if (begin() > Ptr || advance(Ptr, Size) >= end()) {
    if (LastHeap)
      return LastHeap->read<T>(Ptr, Base, Size);
    if (VERBOSE)
      printf("Out of bound read at %p < %p:%p < %p\n", begin(), Ptr,
             advance(Ptr, sizeof(T)), end());
    return *reinterpret_cast<T *>(Ptr);
  }
  if (!isUsed(Ptr, Size)) {
    int32_t ObjIdx = -1;
    T V = getInputGenRT().getNewValue<T>(&ObjIdx);
    write((T *)Ptr, V, Size, true, ObjIdx);
    assert(isUsed(Ptr, Size));
  }
  assert(begin() <= Ptr && advance(Ptr, Size) < end());
  return *reinterpret_cast<T *>(Ptr);
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
    auto V = getInputGenRT().Heap->read<char>(SrcIt, Src, sizeof(char));
    getInputGenRT().Heap->write<char>(TgtIt, V, sizeof(char));
  }
  return TgtIt;
}
void *__inputgen_memcpy(void *Tgt, void *Src, uint64_t N) {
  return __inputgen_memmove(Tgt, Src, N);
}

void *__inputgen_memset(void *Tgt, char C, uint64_t N) {
  char *TgtIt = (char *)Tgt;
  for (uintptr_t I = 0; I < N; ++I, ++TgtIt) {
    getInputGenRT().Heap->write<char>(TgtIt, C, sizeof(char));
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
      getInputGenRT().Heap->read<TY>(Ptr, Base, Size);                         \
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
      getInputGenRT().Heap->write<TY>((TY *)Ptr, TyVal, Size);                 \
      return;                                                                  \
    default:                                                                   \
      abort();                                                                 \
    }                                                                          \
  }                                                                            \
  void __record_read_##NAME(void *Ptr, int64_t Val, int32_t Size, void *Base,  \
                            int32_t Kind) {                                    \
    switch (Kind) {                                                            \
    case 0:                                                                    \
      getInputGenRT().Heap->read<TY>(Ptr, Base, Size);                         \
      return;                                                                  \
    case 1:                                                                    \
      getInputGenRT().Heap->write<TY>((TY *)Ptr, (TY)Val, Size);               \
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
      getInputGenRT().Heap->read<TY>(Ptr, Base, Size);                         \
      return;                                                                  \
    case 1:                                                                    \
      TyVal = *(TY *)Val;                                                      \
      getInputGenRT().Heap->write<TY>((TY *)Ptr, TyVal, Size);                 \
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
