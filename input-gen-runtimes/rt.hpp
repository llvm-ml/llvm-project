#ifndef _INPUT_GEN_RUNTIMES_RT_H_
#define _INPUT_GEN_RUNTIMES_RT_H_

#include <cstdint>
#include <fstream>

namespace {
extern int VERBOSE;
}

#define INPUTGEN_DEBUG(X)                                                      \
  do {                                                                         \
    if (VERBOSE) {                                                             \
      X;                                                                       \
    }                                                                          \
  } while (0)

// Must be a power of 2
// static constexpr intptr_t MaxObjectSize = 1ULL << 32;
// static constexpr intptr_t MinObjAllocation = 1024;
// static constexpr intptr_t ObjAlignment = 16;
//
// static constexpr intptr_t PtrInObjMask = MaxObjectSize - 1;
// static constexpr intptr_t ObjIdxMask = ~(PtrInObjMask);

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
  size_t globalPtrToObjIdx(VoidPtrTy GlobalPtr) {
    size_t Idx =
        (reinterpret_cast<intptr_t>(GlobalPtr) & ObjIdxMask) / MaxObjectSize;
    return Idx;
  }

  VoidPtrTy globalPtrToLocalPtr(VoidPtrTy GlobalPtr) {
    return reinterpret_cast<VoidPtrTy>(reinterpret_cast<intptr_t>(GlobalPtr) &
                                       PtrInObjMask);
  }

  VoidPtrTy getObjBasePtr() {
    return reinterpret_cast<VoidPtrTy>(MaxObjectSize / 2);
  }

  intptr_t getOffsetFromObjBasePtr(VoidPtrTy Ptr) {
    return Ptr - getObjBasePtr();
  }

  VoidPtrTy localPtrToGlobalPtr(size_t ObjIdx, VoidPtrTy PtrInObj) {
    return reinterpret_cast<VoidPtrTy>((ObjIdx * MaxObjectSize) |
                                       reinterpret_cast<intptr_t>(PtrInObj));
  }

  intptr_t PtrInObjMask;
  intptr_t ObjIdxMask;
  uintptr_t MaxObjectSize;
  uintptr_t MaxObjectNum;

  unsigned int highestOne(uint64_t X) { return 63 ^ __builtin_clzll(X); }

  void setSize(uintptr_t Size) {
    uintptr_t HO = highestOne(Size | 1);
    uintptr_t BitsForObj = HO * 3 / 4;
    MaxObjectSize = 1ULL << BitsForObj;
    MaxObjectNum = 1ULL << (HO - BitsForObj);
    PtrInObjMask = MaxObjectSize - 1;
    ObjIdxMask = ~(PtrInObjMask);
  }
};

#endif // _INPUT_GEN_RUNTIMES_RT_H_
