#include <algorithm>
#include <array>
#include <bitset>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sys/resource.h>
#include <sys/wait.h>
#include <type_traits>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "rt-common.hpp"

static void *(*RealMalloc)(size_t) = nullptr;
static void (*RealFree)(void *) = nullptr;

template <class T> struct IRAllocator {
  typedef T value_type;

  IRAllocator() = default;

  template <class U> constexpr IRAllocator(const IRAllocator<U> &) noexcept {}

  T *allocate(size_t Size) {
    T *Ptr = static_cast<T *>(RealMalloc(Size * sizeof(T)));
    if (!Ptr)
      abort();
    INPUTGEN_DEBUG(std::cerr << "[IRAllocator] Allocated " << toVoidPtr(Ptr)
                             << " Size " << Size << "x" << sizeof(T)
                             << std::endl);
    return Ptr;
  }

  void deallocate(T *Ptr, size_t Size) noexcept {
    INPUTGEN_DEBUG(std::cerr << "[IRAllocator] Freeing " << toVoidPtr(Ptr)
                             << " Size " << Size << "x" << sizeof(T)
                             << std::endl);
    RealFree(Ptr);
  }
};
template <class T, class U>
bool operator==(const IRAllocator<T> &, const IRAllocator<U> &) {
  return true;
}
template <class T, class U>
bool operator!=(const IRAllocator<T> &, const IRAllocator<U> &) {
  return false;
}

template <typename T> using IRVector = std::vector<T, IRAllocator<T>>;
using IRString =
    std::basic_string<char, std::char_traits<char>, IRAllocator<char>>;

#include "rt-dump-input.hpp"

using BranchHint = llvm::inputgen::BranchHint;

template <typename T, typename... _Args>
std::unique_ptr<T> IRMakeUnique(_Args &&...Args) {
  IRAllocator<T> A;
  std::unique_ptr<T> UP(A.allocate(1));
  new (UP.get()) T(std::forward<_Args>(Args)...);
  return UP;
}

struct InputRecordConfTy {
  IRString InputOutName;
  InputRecordConfTy() {
    if (char *Str = getenv("INPUT_RECORD_FILENAME"))
      InputOutName = Str;
    else
      // FIXME
      InputOutName = "/dev/null";
  }
};

struct InputRecordRTTy {

  struct InputRecordObjectAddressing : public ObjectAddressing {
    VoidPtrTy getObjBasePtr() const override { return nullptr; }
    VoidPtrTy getLowestObjPtr() const override { abort(); }
    uintptr_t getMaxObjectSize() const override { abort(); }

    InputRecordRTTy &RT;
    InputRecordObjectAddressing(InputRecordRTTy &RT) : RT(RT) {}

    VoidPtrTy globalPtrToLocalPtr(VoidPtrTy GlobalPtr) const {
      auto Res = RT.globalPtrToObjAndLocalPtr(GlobalPtr);
      assert(Res);
      return Res->second;
    }
    VoidPtrTy localPtrToGlobalPtr(size_t ObjIdx, VoidPtrTy PtrInObj) const {
      return RT.Objects[ObjIdx]->getGlobalPtr(PtrInObj);
    }

    uintptr_t getSize() { return std::numeric_limits<uintptr_t>::max(); };
  };
  friend struct InputRecordObjectAddressing;

  InputRecordRTTy(InputRecordConfTy Conf) : Conf(Conf), OA(*this) {
    OutputObjIdxOffset = 0;
  }
  ~InputRecordRTTy() {}

  InputRecordConfTy Conf;

  VoidPtrTy StackPtr;
  intptr_t OutputObjIdxOffset;
  IRString FuncIdent;
  IRString OutputDir;
  std::filesystem::path ExecPath;
  std::mt19937 Gen;
  InputRecordObjectAddressing OA;

  struct GlobalTy {
    VoidPtrTy Ptr;
    size_t ObjIdx;
    uintptr_t Size;
  };
  IRVector<GlobalTy> Globals;
  IRVector<intptr_t> FunctionPtrs;

  uint64_t NumNewValues = 0;

  IRVector<GenValTy> GenVals;
  uint32_t NumArgs = 0;

  // Storage for dynamic objects
  IRVector<std::unique_ptr<ObjectTy>> Objects;
  IRVector<size_t> GlobalBundleObjects;

  int rand() { abort(); }

  struct NewObj {
    size_t Idx;
    VoidPtrTy Ptr;
  };
  static constexpr size_t NullPtrIdx = -1;
  static constexpr uint64_t UnknownSize = -1;
  NewObj getNewPtr(uint64_t Size) { abort(); }

  NewObj getNewGlobal(uint64_t Size) { abort(); }

  size_t getObjIdx(VoidPtrTy GlobalPtr, bool AllowNull = false) { abort(); }

  // Returns nullptr if it is not an object managed by us - a stack pointer or
  // memory allocated by malloc
  ObjectTy *globalPtrToObj(VoidPtrTy GlobalPtr, bool AllowNull = false) {
    for (auto &Obj : Objects)
      if (Obj->isGlobalPtrInObject(GlobalPtr))
        return &*Obj;
    return nullptr;
  }
  std::optional<std::pair<ObjectTy *, VoidPtrTy>>
  globalPtrToObjAndLocalPtr(VoidPtrTy GlobalPtr) {
    for (auto &Obj : Objects)
      if (Obj->isGlobalPtrInObject(GlobalPtr))
        return std::make_pair(&*Obj, Obj->getLocalPtr(GlobalPtr));
    return {};
  }

  template <typename T> T generateNewArg(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> void recordArg(T Val) {
    if constexpr (!std::is_same<T, __int128>::value) {
      if constexpr (std::is_pointer<T>::value)
        INPUTGEN_DEBUG(std::cerr << "Recorded arg " << toVoidPtr(Val)
                                 << std::endl);
      else
        INPUTGEN_DEBUG(std::cerr << "Recorded arg " << Val << std::endl);
    }
    GenVals.push_back(toGenValTy(Val, std::is_pointer<T>::value));
    NumArgs++;
  }

  template <typename T>
  T generateNewStubReturn(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> T getDefaultNewValue() { abort(); }

  template <typename T> T getNewValue(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <>
  VoidPtrTy getNewValue<VoidPtrTy>(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <>
  FunctionPtrTy getNewValue<FunctionPtrTy>(BranchHint *BHs, int32_t BHSize) {
    abort();
  }

  template <typename T> void write(VoidPtrTy Ptr, T Val, uint32_t Size) {
    if (!Recording)
      return;
    assert(Ptr);
    auto Res = globalPtrToObjAndLocalPtr(Ptr);
    // FIXME need globals and stack handling
    assert(Res);
    auto [Obj, LocalPtr] = *Res;
    INPUTGEN_DEBUG(std::cerr << "Write to obj #" << Obj->getIdx()
                             << " with size " << Size << "\n");
    if (Obj)
      Obj->write<T>(Val, LocalPtr, Size);
  }

  template <typename T>
  void read(VoidPtrTy Ptr, VoidPtrTy Base, uint32_t Size, BranchHint *BHs,
            int32_t BHSize) {
    if (!Recording)
      return;
    assert(Ptr);
    auto Res = globalPtrToObjAndLocalPtr(Ptr);
    // FIXME need globals and stack handling
    assert(Res);
    auto [Obj, LocalPtr] = *Res;
    INPUTGEN_DEBUG(std::cerr << "read from obj #" << Obj->getIdx()
                             << " with size " << Size << "\n");
    if (Obj)
      Obj->read<T>(LocalPtr, Size, BHs, BHSize);
  }

  // TODO need to think what happens when we free some memory and subsequently
  // the _same_ location is allocated (with different size for example) Also do
  // we need a hijacked fake `free` function in the replay so that we dont crash
  // when trying to free a non-freeable object?
  void atFree(VoidPtrTy Ptr) {
    INPUTGEN_DEBUG(std::cerr << "Free " << toVoidPtr(Ptr) << std::endl);
  }

  void atMalloc(VoidPtrTy Ptr, size_t Size) {
    size_t Idx = Objects.size();
    INPUTGEN_DEBUG(std::cerr << "Malloc " << toVoidPtr(Ptr) << " Size " << Size
                             << " -> Obj #" << Idx << std::endl);
    Objects.push_back(
        IRMakeUnique<ObjectTy>(RealMalloc, RealFree, Idx, OA, Ptr, Size));
  }

  void registerGlobal(VoidPtrTy, VoidPtrTy *ReplGlobal, int32_t GlobalSize) {
    std::cerr << "register global not implemented yet\n";
    abort();
    auto Global = getNewGlobal(GlobalSize);
    Globals.push_back({Global.Ptr, Global.Idx, (uintptr_t)GlobalSize});
    *ReplGlobal = Global.Ptr;
    INPUTGEN_DEBUG(printf("Global %p replaced with Obj %zu @ %p\n",
                          (void *)ReplGlobal, Global.Idx, (void *)Global.Ptr));
  }

  void registerFunctionPtrAccess(VoidPtrTy Ptr, uint32_t Size,
                                 VoidPtrTy *PotentialFPs, uint64_t N) {
    abort();
  }

  intptr_t registerFunctionPtrIdx(size_t N) { abort(); }

  void report() {
    std::ofstream InputOutStream(Conf.InputOutName.c_str(),
                                 std::ios::out | std::ios::binary);
    dumpInput<InputRecordRTTy>(InputOutStream, *this);
  }

  bool Recording = false;
  bool Done = false;
  void recordPush() {
    if (Done)
      return;
    if (Recording) {
      std::cerr << "Nested recording! Abort!" << std::endl;
      abort();
    }
    INPUTGEN_DEBUG(std::cout << "Start recording\n");
    Recording = true;
  }
  void recordPop() {
    if (Done)
      return;
    if (!Recording) {
      std::cerr << "Pop without push? Abort!" << std::endl;
      abort();
    }
    INPUTGEN_DEBUG(std::cout << "Stop recording\n");
    Recording = false;
    report();
    Done = true;
  }
};

static struct InputRecordRTInit {
  bool Initialized = false;
  std::unique_ptr<InputRecordRTTy> IRRT = nullptr;
  InputRecordRTInit() {
    IRAllocator<InputRecordRTTy> A;
    IRRT.reset(A.allocate(1));
    new (IRRT.get()) InputRecordRTTy(InputRecordConfTy());
    Initialized = true;
  }
} InputRecordRT;
static InputRecordRTTy &getInputRecordRT() { return *InputRecordRT.IRRT; }
static bool &isRTInitialized() { return InputRecordRT.Initialized; }

template <typename T>
void ObjectTy::read(VoidPtrTy Ptr, uint32_t Size, BranchHint *BHs,
                    int32_t BHSize) {
  intptr_t Offset = OA.getOffsetFromObjBasePtr(Ptr);
  assert(Output.isAllocated(Offset, Size));
  Used.ensureAllocation(Offset, Size);
  Input.ensureAllocation(Offset, Size);

  if (allUsed(Offset, Size))
    return;

  T *OutputLoc = reinterpret_cast<T *>(
      advance(Output.Memory, -Output.AllocationOffset + Offset));
  T Val = *OutputLoc;
  // FIXME redundant store - we use the function to mark the correct memory as
  // used, etc
  storeInputValue(Val, Offset, Size);

  if constexpr (std::is_pointer<T>::value)
    Ptrs.insert(Offset);
}

void *malloc(size_t Size) {
  static void *(*LRealMalloc)(size_t) = []() {
    RealMalloc =
        reinterpret_cast<decltype(RealMalloc)>(dlsym(RTLD_NEXT, "malloc"));
    return RealMalloc;
  }();
  void *Mem = LRealMalloc(Size);
  if (isRTInitialized())
    getInputRecordRT().atMalloc(reinterpret_cast<VoidPtrTy>(Mem), Size);
  return Mem;
}

void free(void *Ptr) {
  static void (*LRealFree)(void *) = []() {
    RealFree = reinterpret_cast<decltype(RealFree)>(dlsym(RTLD_NEXT, "free"));
    return RealFree;
  }();
  if (isRTInitialized())
    getInputRecordRT().atFree(reinterpret_cast<VoidPtrTy>(Ptr));
  LRealFree(Ptr);
}

// We need to run this before all other code that may use malloc or free, so
// priority is set to 101. 0-100 are reserved apparently. Even with 101 priority
// we get some malloc before we can get the RealMalloc which is why there is
// code for that in malloc() as well.
__attribute__((constructor(101))) static void hijackMallocAndFree() {
  RealMalloc =
      reinterpret_cast<decltype(RealMalloc)>(dlsym(RTLD_NEXT, "malloc"));
  RealFree = reinterpret_cast<decltype(RealFree)>(dlsym(RTLD_NEXT, "free"));
}

extern "C" {
void __record_push() { getInputRecordRT().recordPush(); }
void __record_pop() { getInputRecordRT().recordPop(); }
}

#define __IG_OBJ__ getInputRecordRT()
#include "rt-common-interface.def"
extern "C" {
DEFINE_INTERFACE(record)
}
