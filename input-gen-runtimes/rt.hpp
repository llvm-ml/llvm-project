#ifndef _INPUT_GEN_RUNTIMES_RT_H_
#define _INPUT_GEN_RUNTIMES_RT_H_

#include <cstdint>
#include <fstream>
#include <iostream>

namespace {
extern int VERBOSE;
}

#ifndef NDEBUG
#define INPUTGEN_DEBUG(X)                                                      \
  do {                                                                         \
    if (VERBOSE) {                                                             \
      X;                                                                       \
    }                                                                          \
  } while (0)
#else
#define INPUTGEN_DEBUG(X)
#endif

static constexpr intptr_t ObjAlignment = 16;
static constexpr intptr_t MaxPrimitiveTypeSize = 16;

typedef uint8_t *VoidPtrTy;

template <typename T> static char *ccast(T *Ptr) {
  return reinterpret_cast<char *>(Ptr);
}

template <typename T> static T readV(std::ifstream &Input) {
  T El;
  Input.read(ccast(&El), sizeof(El));
  return El;
}

template <typename T> static T writeV(std::ofstream &Output, T El) {
  Output.write(ccast(&El), sizeof(El));
  return El;
}

struct ObjectAddressing {
  size_t globalPtrToObjIdx(VoidPtrTy GlobalPtr) const {
    size_t Idx =
        (reinterpret_cast<intptr_t>(GlobalPtr) & ObjIdxMask) / MaxObjectSize;
    return Idx;
  }

  VoidPtrTy globalPtrToLocalPtr(VoidPtrTy GlobalPtr) const {
    return reinterpret_cast<VoidPtrTy>(reinterpret_cast<intptr_t>(GlobalPtr) &
                                       PtrInObjMask);
  }

  VoidPtrTy getObjBasePtr() const {
    return reinterpret_cast<VoidPtrTy>(MaxObjectSize / 2);
  }

  intptr_t getOffsetFromObjBasePtr(VoidPtrTy Ptr) const {
    return Ptr - getObjBasePtr();
  }

  VoidPtrTy localPtrToGlobalPtr(size_t ObjIdx, VoidPtrTy PtrInObj) const {
    return reinterpret_cast<VoidPtrTy>((ObjIdx * MaxObjectSize) |
                                       reinterpret_cast<intptr_t>(PtrInObj));
  }

  intptr_t PtrInObjMask;
  intptr_t ObjIdxMask;
  uintptr_t MaxObjectSize;
  uintptr_t MaxObjectNum;

  uintptr_t Size;

  unsigned int highestOne(uint64_t X) { return 63 ^ __builtin_clzll(X); }

  void setSize(uintptr_t Size) {
    this->Size = Size;

    uintptr_t HO = highestOne(Size | 1);
    uintptr_t BitsForObj = HO * 3 / 4;
    MaxObjectSize = 1ULL << BitsForObj;
    MaxObjectNum = 1ULL << (HO - BitsForObj);
    PtrInObjMask = MaxObjectSize - 1;
    ObjIdxMask = ~(PtrInObjMask);
  }
};

static std::string getFunctionNameFromFile(std::string FileName,
                                           std::string FuncIdent) {
  std::string OriginalFuncName;
  std::ifstream In(FileName);
  std::string Id;
  while (std::getline(In, Id, '\0') &&
         std::getline(In, OriginalFuncName, '\0') && Id != FuncIdent)
    ;
  if (Id != FuncIdent) {
    std::cerr << "Could not find function with ID " << FuncIdent << " in "
              << FileName << std::endl;
    abort();
  }
  return OriginalFuncName;
}

static void useValue(VoidPtrTy Ptr, uint32_t Size) {
  if (getenv("___INPUT_GEN_USE___"))
    for (unsigned I = 0; I < Size; I++)
      printf("%c\n", *(Ptr + Size));
}

#endif // _INPUT_GEN_RUNTIMES_RT_H_
