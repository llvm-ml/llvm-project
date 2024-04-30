#ifndef _INPUT_GEN_RUNTIMES_RT_H_
#define _INPUT_GEN_RUNTIMES_RT_H_

#include <cstdint>
#include <fstream>

// Must be a power of 2
static constexpr intptr_t MaxObjectSize = 1ULL << 32;
static constexpr intptr_t MinObjAllocation = 1024;
static constexpr intptr_t ObjAlignment = 16;

static constexpr intptr_t PtrInObjMask = MaxObjectSize - 1;
static constexpr intptr_t ObjIdxMask = ~(PtrInObjMask);

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

[[maybe_unused]] static size_t globalPtrToObjIdx(VoidPtrTy GlobalPtr) {
  size_t Idx =
      (reinterpret_cast<intptr_t>(GlobalPtr) & ObjIdxMask) / MaxObjectSize;
  return Idx;
}

[[maybe_unused]] static VoidPtrTy globalPtrToLocalPtr(VoidPtrTy GlobalPtr) {
  return reinterpret_cast<VoidPtrTy>(reinterpret_cast<intptr_t>(GlobalPtr) &
                                     PtrInObjMask);
}

[[maybe_unused]] static VoidPtrTy getObjBasePtr() {
  return reinterpret_cast<VoidPtrTy>(MaxObjectSize / 2);
}

[[maybe_unused]] static intptr_t getOffsetFromObjBasePtr(VoidPtrTy Ptr) {
  return Ptr - getObjBasePtr();
}

#endif // _INPUT_GEN_RUNTIMES_RT_H_
