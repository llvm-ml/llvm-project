#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iostream>
#include <map>
#include <random>
#include <vector>

#include <sys/mman.h>

#include "rt-common.hpp"

namespace {
int VERBOSE = 0;
int TIMING = 0;

INPUTGEN_TIMER_DEFINE(IRInitialization);
INPUTGEN_TIMER_DEFINE(IRRun);

} // namespace

struct ReplayObjectTy {
  VoidPtrTy Start;
  intptr_t InputSize;
  intptr_t InputOffset;
  intptr_t OutputSize;
  intptr_t OutputOffset;
};

static unsigned NumStubs;
static VoidPtrTy StubsMemory = nullptr;
static unsigned CurStub = 0;

struct GlobalTy {
  VoidPtrTy Ptr;
  VoidPtrTy InputStart;
  uintptr_t InputSize;
};
static std::vector<GlobalTy> Globals;
static size_t CurGlobal = 0;

static std::vector<intptr_t> FunctionPtrs;
static size_t CurFunctionPtr = 0;

static std::mt19937 Gen;
static std::uniform_int_distribution<> Rand;
int rand() { return Rand(Gen); }

template <typename T> T getNewValue() {
  static_assert(sizeof(T) <= MaxPrimitiveTypeSize);
  assert(CurStub < NumStubs);
  T A;
  memcpy(&A, StubsMemory + CurStub * MaxPrimitiveTypeSize, sizeof(A));
  CurStub++;
  return A;
}

extern "C" {
extern VoidPtrTy __inputrun_function_pointers[];
extern uint32_t __inputrun_num_function_pointers;

void __inputrun_unreachable(int32_t No, const char *Name) {
  printf("Reached unreachable %i due to '%s'\n", No, Name ? Name : "n/a");
  exit(UnreachableExitStatus);
}

void __inputrun_global(int32_t NumGlobals, VoidPtrTy Global, void **ReplGlobal,
                       int32_t GlobalSize) {
  assert(Globals.size() > CurGlobal);
  auto G = Globals[CurGlobal];
  assert(G.Ptr <= G.InputStart &&
         G.InputStart + G.InputSize <= G.Ptr + GlobalSize);
  intptr_t Offset = G.InputStart - G.Ptr;
  assert(Offset >= 0);
  memcpy(Global + Offset, G.InputStart, G.InputSize);
  INPUTGEN_DEBUG(printf("G #%lu at %p Copying input from %p size %zu\n",
                        CurGlobal, (void *)Global, (void *)G.InputStart,
                        G.InputSize));
  CurGlobal++;
}

VoidPtrTy __inputgen_select_fp(VoidPtrTy *FPCandidates, uint64_t N) {
  assert(FunctionPtrs.size() > CurFunctionPtr);
  auto *FunctionPtr = FPCandidates[FunctionPtrs[CurFunctionPtr]];
  CurFunctionPtr++;
  return FunctionPtr;
}

#define RW(TY, NAME)                                                           \
  TY __inputrun_get_##NAME(void *, int32_t) { return getNewValue<TY>(); }

RW(bool, i1)
RW(char, i8)
RW(short, i16)
RW(int32_t, i32)
RW(int64_t, i64)
RW(float, float)
RW(double, double)
RW(VoidPtrTy, ptr)
RW(__int128, i128)
RW(long double, x86_fp80)

#undef RW

void __inputrun_use(VoidPtrTy Ptr, uint32_t Size) { useValue(Ptr, Size); }
void __inputgen_override_free(void *P) {}
}

int main(int argc, char **argv) {
  VERBOSE = (bool)getenv("VERBOSE");
  TIMING = (bool)getenv("TIMING");

  if (argc != 4 && argc != 5 && argc != 2) {
    std::cerr << "Wrong usage." << std::endl;
    return 1;
  }

  char *InputName = argv[1];
  std::string FuncName = ("__inputrun_entry");
  if (argc == 4) {
    std::string Type = argv[2];
    if (Type == "--name") {
      FuncName += "___inputgen_renamed_";
      FuncName += argv[3];
    } else {
      std::cerr << "Wrong usage." << std::endl;
      abort();
    }
  }
  if (argc == 5) {
    std::string Type = argv[2];
    if (Type == "--file") {
      FuncName += "___inputgen_renamed_";
      FuncName += getFunctionNameFromFile(argv[3], argv[4]);
    } else {
      std::cerr << "Wrong usage." << std::endl;
      abort();
    }
  }

  printf("Replay %s\n", InputName);

  INPUTGEN_TIMER_START(IRInitialization);

  std::ifstream Input(InputName, std::ios::in | std::ios::binary);

  auto OASize = readV<uintptr_t>(Input);
  InputGenObjectAddressing OA;
  OA.setSize(OASize);

  auto ObjIdxOffset = readV<uintptr_t>(Input);

  auto Seed = readV<uint32_t>(Input);
  Gen.seed(Seed);

  auto MemSize = readV<uint64_t>(Input);
  char *Memory = ccast(calloc(MemSize, 1));
  INPUTGEN_DEBUG(printf("MemSize %lu : %p\n", MemSize, (void *)Memory));

  static constexpr size_t PtrCmpRegionSize =
      (uintptr_t)64 /*G*/ * 1024 /*M*/ * 1024 /*K*/ * 1024;
  void *PtrCmpRegion = reinterpret_cast<VoidPtrTy>(
      mmap(nullptr, PtrCmpRegionSize, PROT_NONE,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0));
  if (PtrCmpRegion == MAP_FAILED) {
    perror("PtrCmpRegion allocation failed");
    free(Memory);
    exit(1);
  }

  auto NumObjects = readV<uint32_t>(Input);
  INPUTGEN_DEBUG(printf("NO %u\n", NumObjects));
  VoidPtrTy CurMemory = (VoidPtrTy)Memory;
  // Increment by 1 just in case because apparently mmap can return a valid null
  // pointer
  VoidPtrTy CurPtrCmpMemory = (VoidPtrTy)PtrCmpRegion + 1;
  std::vector<ReplayObjectTy> Objects;
  for (uint32_t I = 0; I < NumObjects; I++) {
    [[maybe_unused]] auto Idx = readV<uintptr_t>(Input);
    assert(I == Idx);
    auto InputSize = readV<intptr_t>(Input);
    auto InputOffset = readV<intptr_t>(Input);
    auto OutputSize = readV<intptr_t>(Input);
    auto OutputOffset = readV<intptr_t>(Input);
    auto CmpSize = readV<intptr_t>(Input);
    auto CmpOffset = readV<intptr_t>(Input);
    INPUTGEN_DEBUG(printf("O #%u -> input size %ld offset %ld, output size %ld "
                          "offset %ld, cmp size %ld offset %ld at %p\n",
                          I, InputSize, InputOffset, OutputSize, OutputOffset,
                          CmpSize, CmpOffset, (void *)CurMemory));
    VoidPtrTy ObjStart = CurMemory;
    CurMemory += OutputSize;
    if (OutputSize == 0) {
      assert(InputSize == 0);
      // This means this object was never dereferenced. We still however need to
      // reserve memory space for it in order to ensure no comparisons between
      // different objects succeed/fail on accident because we relocated the
      // pointers
      ObjStart = CurPtrCmpMemory;

      // Just in case make the object at least 1 byte because it may have been
      // cast to a integer and then compared and we would then have missed the
      // comparison
      CmpSize = std::max(CmpSize, (intptr_t)1);

      CurPtrCmpMemory += CmpSize;
      OutputSize = CmpSize;
      OutputOffset = CmpOffset;
    } else {
      assert(CmpSize == 0);
    }
    Objects.push_back(
        {ObjStart, InputSize, InputOffset, OutputSize, OutputOffset});
    Input.read(ccast(ObjStart - OutputOffset + InputOffset), InputSize);
  }

  auto RelocatePointer = [&](VoidPtrTy *PtrLoc, const char *Type) {
    INPUTGEN_DEBUG(printf("Reading pointer from %p\n", (void *)PtrLoc));
    VoidPtrTy GlobalPtr = *PtrLoc;
    if (GlobalPtr == nullptr) {
      printf("Relocate %s %p -> %p\n", Type, (void *)GlobalPtr,
             (void *)nullptr);
      return;
    }
    VoidPtrTy LocalPtr = OA.globalPtrToLocalPtr(GlobalPtr);
    ReplayObjectTy Obj =
        Objects[OA.globalPtrToObjIdx(GlobalPtr) - ObjIdxOffset];
    intptr_t Offset = OA.getOffsetFromObjBasePtr(LocalPtr);
    VoidPtrTy RealPtr = Obj.Start - Obj.OutputOffset + Offset;
    *PtrLoc = RealPtr;
    INPUTGEN_DEBUG(printf("Relocate %s %p -> %p\n", Type, (void *)GlobalPtr,
                          (void *)RealPtr));
  };

  auto NumGlobals = readV<uint32_t>(Input);
  INPUTGEN_DEBUG(printf("NG %u\n", NumGlobals));
  for (uint32_t I = 0; I < NumGlobals; I++) {
    VoidPtrTy Ptr = readV<VoidPtrTy>(Input);
    VoidPtrTy InputStart = readV<VoidPtrTy>(Input);
    uintptr_t InputSize = readV<uintptr_t>(Input);
    RelocatePointer(&Ptr, "Global Start");
    RelocatePointer(&InputStart, "Global Input");
    Globals.push_back({Ptr, InputStart, InputSize});
    INPUTGEN_DEBUG(printf("G #%u -> #%p input start %p size %zu\n", I,
                          (void *)Ptr, (void *)InputStart, InputSize));
  }

  for (uint32_t I = 0; I < NumObjects; I++) {
    [[maybe_unused]] auto Idx = readV<uintptr_t>(Input);
    assert(Idx == I);
    auto NumPtrs = readV<uintptr_t>(Input);
    INPUTGEN_DEBUG(printf("O #%u NP %lu\n", I, NumPtrs));
    auto Obj = Objects[I];
    for (uintptr_t J = 0; J < NumPtrs; J++) {
      auto PtrOffset = readV<intptr_t>(Input);
      VoidPtrTy *PtrLoc = reinterpret_cast<VoidPtrTy *>(
          Obj.Start - Obj.OutputOffset + PtrOffset);
      RelocatePointer(PtrLoc, "Obj");
    }
    uintptr_t NumFPtrs = readV<uintptr_t>(Input);
    INPUTGEN_DEBUG(printf("O #%u NFP %lu\n", I, NumFPtrs));
    for (uintptr_t J = 0; J < NumFPtrs; J++) {
      auto PtrOffset = readV<intptr_t>(Input);
      auto FPtrIdx = readV<uint32_t>(Input);
      INPUTGEN_DEBUG(printf("FP at %ld : %u\n", PtrOffset, FPtrIdx));
      *reinterpret_cast<VoidPtrTy *>(Obj.Start - Obj.OutputOffset + PtrOffset) =
          __inputrun_function_pointers[FPtrIdx];
    }
  }

  uint32_t NumGenVals = readV<uint32_t>(Input);
  uint32_t NumArgs = readV<uint32_t>(Input);
  VoidPtrTy ArgsMemory =
      reinterpret_cast<VoidPtrTy>(calloc(NumGenVals, MaxPrimitiveTypeSize));
  INPUTGEN_DEBUG(printf("GenVals %u : %p\n", NumGenVals, (void *)ArgsMemory));
  for (uint32_t I = 0; I < NumGenVals; ++I) {
    VoidPtrTy CurMem = ArgsMemory + I * MaxPrimitiveTypeSize;
    Input.read(ccast(CurMem), MaxPrimitiveTypeSize);
    auto IsPtr = readV<int32_t>(Input);
    INPUTGEN_DEBUG(printf("GenVal #%d : %p\n", I, (void *)ArgsMemory));
    if (IsPtr)
      RelocatePointer(reinterpret_cast<VoidPtrTy *>(CurMem), "GenVal");
  }

  uint32_t NumGenFunctionPtrs = readV<uint32_t>(Input);
  INPUTGEN_DEBUG(printf("NFP %u\n", NumGenFunctionPtrs));
  FunctionPtrs.reserve(NumGenFunctionPtrs);
  for (uint32_t I = 0; I < NumGenFunctionPtrs; I++) {
    auto FpIdx = readV<intptr_t>(Input);
    FunctionPtrs.push_back(FpIdx);
    INPUTGEN_DEBUG(printf("FP #%u -> #%lu\n", I, FpIdx));
  }

  StubsMemory = ArgsMemory + NumArgs * MaxPrimitiveTypeSize;
  NumStubs = NumGenVals - NumArgs;
  INPUTGEN_DEBUG(printf("Args %u : %p\n", NumArgs, (void *)ArgsMemory));
  INPUTGEN_DEBUG(printf("Stubs %u : %p\n", NumStubs, (void *)StubsMemory));

  void *Handle = dlopen(NULL, RTLD_NOW);
  if (!Handle) {
    std::cout << "Could not dyn load binary" << std::endl;
    std::cout << dlerror() << std::endl;
    return 11;
  }
  typedef void (*EntryFnType)(char *);
  EntryFnType EntryFn = (EntryFnType)dlsym(Handle, FuncName.c_str());

  if (!EntryFn) {
    std::cout << "Function " << FuncName << " not found in binary."
              << std::endl;
    return 12;
  }

  INPUTGEN_TIMER_END(IRInitialization);
  printf("Run\n");
  INPUTGEN_TIMER_START(IRRun);
  EntryFn(ccast(ArgsMemory));
  INPUTGEN_TIMER_END(IRRun);

  dlclose(Handle);

  // TODO: we intercept free
  free(ArgsMemory);
  free(Memory);
  munmap(PtrCmpRegion, PtrCmpRegionSize);
}
