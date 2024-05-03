#include <cassert>
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

#include "rt.hpp"

namespace {
int VERBOSE = 0;
}

struct ObjectTy {
  VoidPtrTy Start;
  intptr_t Size;
  intptr_t BaseOffset;
};

static unsigned NumStubs;
static VoidPtrTy StubsMemory = nullptr;
static unsigned CurStub = 0;

static std::vector<ObjectTy> Globals;
static size_t CurGlobal = 0;

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
void __inputgen_global(int32_t NumGlobals, VoidPtrTy Global, void **ReplGlobal,
                       int32_t GlobalSize) {
  assert(Globals.size() > CurGlobal);
  ObjectTy Obj = Globals[CurGlobal];
  // We cannot access globals with negative offsets
  assert(Obj.BaseOffset >= 0);
  assert(Obj.Size <= GlobalSize);
  memcpy(Global + Obj.BaseOffset, Obj.Start, Obj.Size);
  CurGlobal++;
}

#define RW(TY, NAME)                                                           \
  TY __inputrun_get_##NAME() { return getNewValue<TY>(); }

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

// void free(void *) {}
}

int main(int argc, char **argv) {
  if (argc != 3 && argc != 2) {
    std::cerr << "Wrong usage." << std::endl;
    return 1;
  }

  char *InputName = argv[1];
  std::string FuncName = ("__inputrun_entry");
  if (argc == 3) {
    FuncName += "___inputgen_renamed_";
    FuncName += argv[2];
  }

  VERBOSE = (bool)getenv("VERBOSE");

  printf("Replay %s\n", InputName);

  std::ifstream Input(InputName, std::ios::in | std::ios::binary);

  auto OASize = readV<uintptr_t>(Input);
  ObjectAddressing OA;
  OA.setSize(OASize);

  auto ObjIdxOffset = readV<uintptr_t>(Input);

  auto Seed = readV<uint32_t>(Input);
  Gen.seed(Seed);

  auto MemSize = readV<uint64_t>(Input);
  char *Memory = ccast(calloc(MemSize, 1));
  INPUTGEN_DEBUG(printf("MemSize %lu : %p\n", MemSize, (void *)Memory));

  auto NumObjects = readV<uint32_t>(Input);
  INPUTGEN_DEBUG(printf("NO %u\n", NumObjects));
  VoidPtrTy CurMemory = (VoidPtrTy)Memory;
  std::vector<ObjectTy> Objects;
  for (uint32_t I = 0; I < NumObjects; I++) {
    [[maybe_unused]] auto Idx = readV<uintptr_t>(Input);
    assert(I == Idx);
    auto Size = readV<intptr_t>(Input);
    auto Offset = readV<intptr_t>(Input);
    INPUTGEN_DEBUG(printf("O #%u -> size %ld offset %ld at %p\n", I, Size,
                          Offset, (void *)CurMemory));
    Objects.push_back({CurMemory, Size, Offset});
    Input.read(ccast(CurMemory), Size);
    CurMemory += Size;
  }

  auto NumGlobals = readV<uint32_t>(Input);
  INPUTGEN_DEBUG(printf("NG %u\n", NumGlobals));
  for (uint32_t I = 0; I < NumGlobals; I++) {
    auto ObjIdx = readV<uint32_t>(Input);
    assert(ObjIdx < NumObjects);
    auto Obj = Objects[ObjIdx];
    Globals.push_back(Obj);
    INPUTGEN_DEBUG(printf("G #%u -> #%u\n", I, ObjIdx));
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
    ObjectTy Obj = Objects[OA.globalPtrToObjIdx(GlobalPtr) - ObjIdxOffset];
    intptr_t Offset = OA.getOffsetFromObjBasePtr(LocalPtr);
    VoidPtrTy RealPtr = Obj.Start + Obj.BaseOffset + Offset;
    *PtrLoc = RealPtr;
    INPUTGEN_DEBUG(printf("Relocate %s %p -> %p\n", Type, (void *)GlobalPtr,
                          (void *)RealPtr));
  };

  for (uint32_t I = 0; I < NumObjects; I++) {
    [[maybe_unused]] auto Idx = readV<uintptr_t>(Input);
    assert(Idx == I);
    auto NumPtrs = readV<uintptr_t>(Input);
    INPUTGEN_DEBUG(printf("O #%u NP %lu\n", I, NumPtrs));
    auto Obj = Objects[I];
    for (uintptr_t J = 0; J < NumPtrs; J++) {
      auto PtrOffset = readV<intptr_t>(Input);
      VoidPtrTy *PtrLoc =
          reinterpret_cast<VoidPtrTy *>(Obj.Start + Obj.BaseOffset + PtrOffset);
      RelocatePointer(PtrLoc, "Obj");
    }
  }

  uint32_t NumGenVals = readV<uint32_t>(Input);
  uint32_t NumArgs = readV<uint32_t>(Input);
  VoidPtrTy ArgsMemory =
      reinterpret_cast<VoidPtrTy>(calloc(NumGenVals, MaxPrimitiveTypeSize));
  INPUTGEN_DEBUG(printf("Args %u : %p\n", NumArgs, (void *)ArgsMemory));
  for (uint32_t I = 0; I < NumGenVals; ++I) {
    VoidPtrTy CurMem = ArgsMemory + I * MaxPrimitiveTypeSize;
    Input.read(ccast(CurMem), MaxPrimitiveTypeSize);
    auto IsPtr = readV<int32_t>(Input);
    INPUTGEN_DEBUG(printf("Arg #%d : %p\n", I, (void *)ArgsMemory));
    if (IsPtr)
      RelocatePointer(reinterpret_cast<VoidPtrTy *>(CurMem), "GenVal");
  }

  StubsMemory = ArgsMemory + NumArgs * MaxPrimitiveTypeSize;
  NumStubs = NumGenVals - NumArgs;
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

  printf("Run\n");
  EntryFn(ccast(ArgsMemory));

  dlclose(Handle);

  // TODO: we intercept free
  free(ArgsMemory);
  free(Memory);
}
