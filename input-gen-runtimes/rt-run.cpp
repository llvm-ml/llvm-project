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

static int VERBOSE = 0;

// TODO

static std::vector<void *> GetObjectPtrs;
static unsigned GetObjectIdx = 0;

static std::vector<char *> Globals;
static size_t GlobalsIt = 0;

static std::mt19937 Gen;
static std::uniform_int_distribution<> Rand;
int rand() { return Rand(Gen); }

template <typename T> T getNewValue() {
  T V = rand() % 10;
  return V;
}

template <> void *getNewValue<void *>() {
  if (!(rand() % 50))
    return nullptr;
  return GetObjectPtrs[GetObjectIdx++];
}

extern "C" {
void __inputgen_global(int32_t NumGlobals, void *Global, void **ReplGlobal,
                       int32_t GlobalSize) {
  assert(Globals.size() > GlobalsIt);
  memcpy(Global, Globals[GlobalsIt], GlobalSize);
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
RW(void *, ptr)

#undef RW

void free(void *) {}
}

int main(int argc, char **argv) {
  if (argc != 3 && argc != 2) {
    std::cerr << "Wrong usage." << std::endl;
    return 1;
  }

  char *InputName = argv[1];
  std::string FuncName = ("__inputrun_entry");
  if (argc == 3) {
    FuncName += "_";
    FuncName += argv[2];
  }

  VERBOSE = (bool)getenv("VERBOSE");

  printf("Replay %s\n", InputName);

  std::ifstream Input(InputName, std::ios::in | std::ios::binary);

  auto Seed = readV<uint32_t>(Input);
  Gen.seed(Seed);

  auto MemSize = readV<uint64_t>(Input);
  char *Memory = ccast(malloc(MemSize));
  if (VERBOSE)
    printf("MemSize %lu : %p\n", MemSize, (void *)Memory);

  auto NumObjects = readV<uint32_t>(Input);
  if (VERBOSE)
    printf("NO %u\n", NumObjects);
  VoidPtrTy CurMemory = (VoidPtrTy)Memory;
  struct ObjectTy {
    VoidPtrTy Start;
    intptr_t BaseOffset;
  };
  std::vector<ObjectTy> Objects;
  for (uint32_t I = 0; I < NumObjects; I++) {
    auto Size = readV<intptr_t>(Input);
    auto Offset = readV<intptr_t>(Input);
    if (VERBOSE)
      printf("O id %u -> size %ld offset %ld\n", I, Size, Offset);
    Objects.push_back({CurMemory, Offset});
    CurMemory += Size;
    Input.read(Memory, Size);
  }

  auto NumGlobals = readV<uint32_t>(Input);
  for (uint32_t I = 0; I < NumGlobals; I++) {
    auto ObjIdx = readV<uint32_t>(Input);
    assert(ObjIdx < NumObjects);
    auto Obj = Objects[ObjIdx];
    VoidPtrTy GlobalMem = Obj.Start + Obj.BaseOffset;
    assert(Obj.BaseOffset >= 0);
    Globals.push_back(ccast(GlobalMem));
    if (VERBOSE)
      printf("G id %u -> id %u, addr %p\n", I, ObjIdx, (void *)GlobalMem);
    // We cannot access globals with negative offsets
  }

  auto RelocatePointer = [&](VoidPtrTy *PtrLoc, const char *Type) {
    VoidPtrTy GlobalPtr = *PtrLoc;
    VoidPtrTy LocalPtr = globalPtrToLocalPtr(GlobalPtr);
    ObjectTy Obj = Objects[globalPtrToObjIdx(GlobalPtr)];
    intptr_t Offset = getOffsetFromObjBasePtr(LocalPtr);
    VoidPtrTy RealPtr = Obj.Start + Obj.BaseOffset + Offset;
    *PtrLoc = RealPtr;
    if (VERBOSE)
      printf("Relocate %s %p -> %p\n", Type, (void *)GlobalPtr,
             (void *)RealPtr);
  };

  for (uint32_t I = 0; I < NumObjects; I++) {
    auto NumPtrs = readV<uint32_t>(Input);
    auto Obj = Objects[I];
    for (uintptr_t J = 0; J < NumPtrs; J++) {
      auto PtrOffset = readV<intptr_t>(Input);
      VoidPtrTy *PtrLoc =
          reinterpret_cast<VoidPtrTy *>(Obj.Start + Obj.BaseOffset + PtrOffset);
      RelocatePointer(PtrLoc, "Obj");
    }
  }

  auto NumArgs = readV<uint32_t>(Input);
  char *ArgsMemory = ccast(malloc(NumArgs * sizeof(uintptr_t)));
  if (VERBOSE)
    printf("Args %u : %p\n", NumArgs, (void *)ArgsMemory);
  for (uint32_t I = 0; I < NumArgs; ++I) {
    auto Content = readV<uintptr_t>(Input);
    auto ObjIdx = readV<int32_t>(Input);
    auto IsPtr = readV<int32_t>(Input);
    if (ObjIdx != -1) {
      assert(ObjIdx < (int64_t)Objects.size());
      printf("ObjIdx = -1 Arg not implemented\n");
      exit(2);
    }
    if (VERBOSE)
      printf("Arg id %d : %p\n", I, (void *)ArgsMemory);
    if (IsPtr)
      RelocatePointer(reinterpret_cast<VoidPtrTy *>(&Content), "Arg");
    memcpy(ArgsMemory + I * sizeof(void *), &Content, sizeof(void *));
  }

  // auto NumGetObjects = readV<uint32_t>(Input);
  // for (uint32_t I = 0; I < NumGetObjects; ++I) {
  //   auto ObjIdx = readV<int32_t>(Input);
  //   assert(ObjIdx);
  //   GetObjectPtrs.push_back(ObjMap[ObjIdx]);
  // }

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
  EntryFn(ArgsMemory);

  dlclose(Handle);

  // TODO: we intercept free
  free(ArgsMemory);
  free(Memory);
}
