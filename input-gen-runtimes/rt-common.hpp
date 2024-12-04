#ifndef _INPUT_GEN_RUNTIMES_RT_H_
#define _INPUT_GEN_RUNTIMES_RT_H_

#include <cstdint>
#include <fstream>
#include <iostream>

#include "../llvm/include/llvm/Transforms/IPO/InputGenerationTypes.h"

using BranchHint = llvm::inputgen::BranchHint;

namespace {
int VERBOSE = 0;
int TIMING = 0;
} // namespace

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

#define INPUTGEN_TIMER_DEFINE(Name)                                            \
  std::chrono::steady_clock::time_point Timer##Name##Begin

#define INPUTGEN_TIMER_START(Name)                                             \
  do {                                                                         \
    if (TIMING)                                                                \
      Timer##Name##Begin = std::chrono::steady_clock::now();                   \
  } while (0)

#define INPUTGEN_TIMER_END(Name)                                               \
  do {                                                                         \
    if (TIMING) {                                                              \
      std::chrono::steady_clock::time_point Timer##Name##End =                 \
          std::chrono::steady_clock::now();                                    \
      std::cout << "Time for " << #Name << ": "                                \
                << std::chrono::duration_cast<std::chrono::nanoseconds>(       \
                       Timer##Name##End - Timer##Name##Begin)                  \
                       .count()                                                \
                << std::endl;                                                  \
    }                                                                          \
  } while (0)

static constexpr intptr_t ObjAlignment = 16;
static constexpr intptr_t MaxPrimitiveTypeSize = 16;

static constexpr int UnreachableExitStatus = 111;

typedef uint8_t *VoidPtrTy;
typedef struct {
} *FunctionPtrTy;

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

  VoidPtrTy getLowestObjPtr() const { return nullptr; }

  intptr_t PtrInObjMask;
  intptr_t ObjIdxMask;
  uintptr_t MaxObjectSize;
  uintptr_t MaxObjectNum;

  uintptr_t Size;

  unsigned int highestOne(uint64_t X) { return 63 ^ __builtin_clzll(X); }

  void setSize(uintptr_t Size) {
    this->Size = Size;

    uintptr_t HO = highestOne(Size | 1);
    uintptr_t BitsForObj = HO * 70 / 100;
    uintptr_t BitsForObjIndexing = HO - BitsForObj;
    MaxObjectSize = 1ULL << BitsForObj;
    MaxObjectNum = 1ULL << (BitsForObjIndexing);
    PtrInObjMask = MaxObjectSize - 1;
    ObjIdxMask = ~(PtrInObjMask);
    INPUTGEN_DEBUG(std::cerr << "OA " << BitsForObj
                             << " bits for in-object addressing and "
                             << BitsForObjIndexing << " for object indexing\n");
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

static constexpr intptr_t MinObjAllocation = 64;
static constexpr unsigned NullPtrProbability = 75;
static constexpr int CmpPtrRetryProbability = 10;
static constexpr int MaxDeviationFromBranchHint = 10;

template <typename T> static T divFloor(T A, T B) {
  assert(B > 0);
  T Res = A / B;
  T Rem = A % B;
  if (Rem == 0)
    return Res;
  if (Rem < 0) {
    assert(A < 0);
    return Res - 1;
  }
  assert(A > 0);
  return Res;
}

template <typename T> static T divCeil(T A, T B) {
  assert(B > 0);
  T Res = A / B;
  T Rem = A % B;
  if (Rem == 0)
    return Res;
  if (Rem > 0) {
    assert(A > 0);
    return Res + 1;
  }
  assert(A < 0);
  return Res;
}

template <typename T> static T alignStart(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(divFloor(IPtr, Alignment) * Alignment);
}

template <typename T> static T alignEnd(T Ptr, intptr_t Alignment) {
  intptr_t IPtr = reinterpret_cast<intptr_t>(Ptr);
  return reinterpret_cast<T>(divCeil(IPtr, Alignment) * Alignment);
}

static VoidPtrTy advance(VoidPtrTy Ptr, uint64_t Bytes) {
  return reinterpret_cast<uint8_t *>(Ptr) + Bytes;
}

struct ObjectTy {
  const ObjectAddressing &OA;
  ObjectTy(size_t Idx, const ObjectAddressing &OA, VoidPtrTy Output,
           bool KnownSizeObjBundle = false)
      : OA(OA), KnownSizeObjBundle(KnownSizeObjBundle), Idx(Idx) {
    this->Output.Memory = Output;
    this->Output.AllocationSize = OA.MaxObjectSize;
    this->Output.AllocationOffset = OA.getOffsetFromObjBasePtr(nullptr);

    if (KnownSizeObjBundle)
      CurrentStaticObjEnd = OA.getObjBasePtr();
  }
  ~ObjectTy() {}

  struct AlignedMemoryChunk {
    VoidPtrTy Ptr;
    intptr_t InputSize;
    intptr_t InputOffset;
    intptr_t OutputSize;
    intptr_t OutputOffset;
    intptr_t CmpSize;
    intptr_t CmpOffset;
  };

  bool KnownSizeObjBundle;
  VoidPtrTy CurrentStaticObjEnd;

  VoidPtrTy addKnownSizeObject(uintptr_t Size) {
    assert(KnownSizeObjBundle);
    // Make sure zero-sized objects have their own address
    if (Size == 0)
      Size = 1;
    if (Size + CurrentStaticObjEnd > OA.getLowestObjPtr() + OA.MaxObjectSize)
      return nullptr;
    VoidPtrTy ObjPtr = CurrentStaticObjEnd;
    CurrentStaticObjEnd = alignEnd(CurrentStaticObjEnd + Size, ObjAlignment);
    return ObjPtr;
  }

  struct KnownSizeObjInputMem {
    VoidPtrTy Start;
    uintptr_t Size;
  };
  KnownSizeObjInputMem getKnownSizeObjectInputMemory(VoidPtrTy LocalPtr,
                                                     uintptr_t Size) {
    assert(KnownSizeObjBundle);
    KnownSizeObjInputMem Mem;
    Mem.Start = std::min(
        LocalPtr + Size,
        std::max(LocalPtr, OA.getObjBasePtr() + InputLimits.LowestOffset));
    VoidPtrTy End = std::max(
        LocalPtr, std::min(LocalPtr + Size,
                           OA.getObjBasePtr() + InputLimits.HighestOffset));
    Mem.Size = End - Mem.Start;
    assert(Mem.Start <= End);
    return Mem;
  }

  void comparedAt(VoidPtrTy Ptr) {
    intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
    CmpLimits.update(Offset, 1);
  }

  AlignedMemoryChunk getAlignedInputMemory() {
    // If we compare the pointer at some offset we need to make sure the output
    // allocation will contain those locations, otherwise comparisons may differ
    // in input-gen and input-run as we would compare against an offset in a
    // different object
    if (!OutputLimits.isEmpty()) {
      if (!CmpLimits.isEmpty())
        OutputLimits.update(CmpLimits.LowestOffset, CmpLimits.getSize());
      // We no longer need the CmpLimits, reset it
      CmpLimits = Limits();
    }

    VoidPtrTy InputStart =
        InputLimits.LowestOffset + Input.Memory - Input.AllocationOffset;
    VoidPtrTy InputEnd =
        InputLimits.HighestOffset + Input.Memory - Input.AllocationOffset;
    intptr_t OutputStart = alignStart(OutputLimits.LowestOffset, ObjAlignment);
    intptr_t OutputEnd = alignEnd(OutputLimits.HighestOffset, ObjAlignment);
    return {InputStart,
            InputEnd - InputStart,
            InputLimits.LowestOffset,
            OutputEnd - OutputStart,
            OutputStart,
            CmpLimits.getSize(),
            CmpLimits.LowestOffset};
  }

  template <typename T>
  T read(VoidPtrTy Ptr, uint32_t Size, BranchHint *BHs, int32_t BHSize);

  template <typename T> void write(T Val, VoidPtrTy Ptr, uint32_t Size) {
    intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
    assert(Output.isAllocated(Offset, Size));
    Used.ensureAllocation(Offset, Size);
    markUsed(Offset, Size);
    OutputLimits.update(Offset, Size);
  }

  void setFunctionPtrIdx(VoidPtrTy Ptr, uint32_t Size, VoidPtrTy FPtr,
                         uint32_t FIdx) {
    intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
    storeGeneratedValue(FPtr, Offset, Size);
    FPtrs.insert({Offset, FIdx});
  }

  const size_t Idx;
  std::set<intptr_t> Ptrs;
  std::unordered_map<intptr_t, uint32_t> FPtrs;

private:
  struct Memory {
    VoidPtrTy Memory = nullptr;
    intptr_t AllocationSize = 0;
    intptr_t AllocationOffset = 0;
    bool isAllocated(intptr_t Offset, uint32_t Size) {
      intptr_t AllocatedMemoryStartOffset = AllocationOffset;
      intptr_t AllocatedMemoryEndOffset =
          AllocatedMemoryStartOffset + AllocationSize;
      return (AllocatedMemoryStartOffset <= Offset &&
              AllocatedMemoryEndOffset > Offset + Size);
    }

    /// Returns true if it was already allocated
    bool ensureAllocation(intptr_t Offset, uint32_t Size) {
      if (isAllocated(Offset, Size))
        return true;
      reallocateData(Offset, Size);
      return false;
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
        NewAllocatedMemoryStartOffset = alignStart(
            std::min(2 * AccessStartOffset, -MinObjAllocation), ObjAlignment);
      }
      if (AccessEndOffset >= AllocatedMemoryEndOffset) {
        // Extend the allocation in the positive direction
        NewAllocatedMemoryEndOffset = alignEnd(
            std::max(2 * AccessEndOffset, MinObjAllocation), ObjAlignment);
      }

      intptr_t NewAllocationOffset = NewAllocatedMemoryStartOffset;
      intptr_t NewAllocationSize =
          NewAllocatedMemoryEndOffset - NewAllocatedMemoryStartOffset;

      INPUTGEN_DEBUG(
          printf("Reallocating data in Object for access at %ld with size %d "
                 "from offset "
                 "%ld, size %ld to offset %ld, size %ld.\n",
                 Offset, Size, AllocationOffset, AllocationSize,
                 NewAllocationOffset, NewAllocationSize));

      extendMemory(Memory, NewAllocationSize, NewAllocationOffset);

      AllocationSize = NewAllocationSize;
      AllocationOffset = NewAllocationOffset;
    }
  };
  Memory Output, Input, Used;

  struct Limits {
    bool Initialized = false;
    intptr_t LowestOffset = 0;
    intptr_t HighestOffset = 0;
    bool isEmpty() { return !Initialized; }
    intptr_t getSize() { return HighestOffset - LowestOffset; }
    void update(intptr_t Offset, uint32_t Size) {
      if (!Initialized) {
        Initialized = true;
        LowestOffset = Offset;
        HighestOffset = Offset + Size;
        return;
      }
      if (LowestOffset > Offset)
        LowestOffset = Offset;
      if (HighestOffset < Offset + Size)
        HighestOffset = Offset + Size;
    }
  };
  Limits InputLimits, OutputLimits, CmpLimits;

  bool allUsed(intptr_t Offset, uint32_t Size) {
    for (unsigned It = 0; It < Size; It++)
      if (!Used.isAllocated(Offset + It, 1) ||
          !Used.Memory[Offset + It - Used.AllocationOffset])
        return false;
    return true;
  }

  void markUsed(intptr_t Offset, uint32_t Size) {
    assert(Used.isAllocated(Offset, Size));

    for (unsigned It = 0; It < Size; It++)
      Used.Memory[Offset + It - Used.AllocationOffset] = 1;
  }

  template <typename T>
  void storeGeneratedValue(T Val, intptr_t Offset, uint32_t Size) {
    assert(Size == sizeof(Val));

    // Only assign the bytes that were uninitialized
    uint8_t Bytes[sizeof(Val)];
    memcpy(Bytes, &Val, sizeof(Val));
    for (unsigned It = 0; It < sizeof(Val); It++) {
      if (!allUsed(Offset + It, 1)) {
        VoidPtrTy OutputLoc =
            Output.Memory - Output.AllocationOffset + Offset + It;
        VoidPtrTy InputLoc =
            Input.Memory - Input.AllocationOffset + Offset + It;
        *OutputLoc = Bytes[It];
        *InputLoc = Bytes[It];
        markUsed(Offset + It, 1);
      }
    }

    InputLimits.update(Offset, Size);
    OutputLimits.update(Offset, Size);
  }
};

#endif // _INPUT_GEN_RUNTIMES_RT_H_
