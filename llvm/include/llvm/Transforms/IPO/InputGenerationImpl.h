#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H

#include "llvm/ADT/EnumeratedArray.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/iterator.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/ProfileData/InstrProfReader.h"
#include "llvm/Support/BLAKE3.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/HashBuilder.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <cstdint>

namespace llvm {

enum IGInstrumentationModeTy { IG_Record, IG_Generate, IG_Run };

struct InterestingMemoryAccess {
  Instruction *I = nullptr;
  Value *Addr = nullptr;
  Type *AccessTy;
  Value *V = nullptr;
  Value *MaybeMask = nullptr;

  enum KindTy { READ, WRITE, READ_THEN_WRITE, Last = READ_THEN_WRITE } Kind;

  static std::string kindAsStr(KindTy K) {
    switch (K) {
    case WRITE:
      return "write";
    case READ:
      return "read";
    case READ_THEN_WRITE:
      return "read_write";
    }
    llvm_unreachable("Unknown kind");
  }
};

/// Instrument the code in module to profile memory accesses.
class InputGenInstrumenter {
public:
  InputGenInstrumenter(Module &M, AnalysisManager<Module> &MAM,
                       IGInstrumentationModeTy Mode,
                       bool InstrumentedForCoverage)
      : Mode(Mode), MAM(MAM), InstrumentedForCoverage(InstrumentedForCoverage) {
    Ctx = &(M.getContext());
    PtrTy = PointerType::getUnqual(*Ctx);
    Int1Ty = IntegerType::getIntNTy(*Ctx, 1);
    Int8Ty = IntegerType::getIntNTy(*Ctx, 8);
    Int16Ty = IntegerType::getIntNTy(*Ctx, 16);
    Int32Ty = IntegerType::getIntNTy(*Ctx, 32);
    Int64Ty = IntegerType::getIntNTy(*Ctx, 64);
    Int128Ty = IntegerType::getIntNTy(*Ctx, 128);
    VoidTy = PointerType::getVoidTy(*Ctx);
    FloatTy = Type::getFloatTy(*Ctx);
    DoubleTy = Type::getDoubleTy(*Ctx);
    X86_FP80Ty = Type::getX86_FP80Ty(*Ctx);
  }

  typedef DenseMap<Type *, FunctionCallee> CallbackCollectionTy;

  /// If it is an interesting memory access, populate information
  /// about the access and return a InterestingMemoryAccess struct.
  /// Otherwise return std::nullopt.
  std::optional<InterestingMemoryAccess>
  isInterestingMemoryAccess(Instruction *I) const;

  void instrumentMop(const InterestingMemoryAccess &Access,
                     const DataLayout &DL);
  void instrumentAddress(const InterestingMemoryAccess &Access,
                         const DataLayout &DL);
  void emitMemoryAccessCallback(IRBuilderBase &IRB, Value *Addr, Value *V,
                                Type *AccessTy, int32_t AllocSize,
                                InterestingMemoryAccess::KindTy Kind,
                                Value *Object);
  void instrumentMaskedLoadOrStore(const InterestingMemoryAccess &Access,
                                   const DataLayout &DL);
  void instrumentMemIntrinsic(MemIntrinsic *MI);

  void instrumentFunction(Function &F);
  void instrumentModuleForEntryPoint(Function &F);
  Value *constructTypeUsingCallbacks(Module &M, IRBuilderBase &IRB,
                                     CallbackCollectionTy &CC, Type *T);
  void createRecordingEntryPoint(Function &F);
  void createGenerationEntryPoint(Function &F, bool UniqName);
  void createRunEntryPoint(Function &F, bool UniqName);
  void createGlobalCalls(Module &M, IRBuilder<> &IRB);
  void stubDeclarations(Module &M, TargetLibraryInfo &TLI);
  void provideGlobals(Module &M);
  SetVector<Function *> pruneModule(Function &F);

  SmallVector<std::pair<GlobalVariable *, GlobalVariable *>>
      MaybeExtInitializedGlobals;

  IGInstrumentationModeTy Mode;
  Type *VoidTy, *FloatTy, *DoubleTy, *X86_FP80Ty;
  IntegerType *Int1Ty, *Int8Ty, *Int16Ty, *Int32Ty, *Int64Ty, *Int128Ty;
  PointerType *PtrTy;
  LLVMContext *Ctx;

  AnalysisManager<Module> &MAM;

  void initializeCallbacks(Module &M);

  bool shouldPreserveFuncName(Function &F, TargetLibraryInfo &TLI);
  bool shouldNotStubFunc(Function &F, TargetLibraryInfo &TLI);
  bool shouldPreserveGVName(GlobalVariable &GV);
  bool shouldNotStubGV(GlobalVariable &GV);

private:
  CallbackCollectionTy InputGenMemoryAccessCallback;
  CallbackCollectionTy StubValueGenCallback;
  CallbackCollectionTy ArgGenCallback;

  FunctionCallee InputGenMemmove, InputGenMemcpy, InputGenMemset;
  FunctionCallee UseCallback;

  bool InstrumentedForCoverage;
};

class ModuleInputGenInstrumenter {
public:
  ModuleInputGenInstrumenter(Module &M, AnalysisManager<Module> &AM,
                             IGInstrumentationModeTy Mode,
                             bool InstrumentedForCoverage)
      : IGI(M, AM, Mode, InstrumentedForCoverage) {
    TargetTriple = Triple(M.getTargetTriple());
    TLII.reset(new TargetLibraryInfoImpl(TargetTriple));
    TLI.reset(new TargetLibraryInfo(*TLII));
  }

  void renameGlobals(Module &M, TargetLibraryInfo &TLI);
  bool instrumentClEntryPoint(Module &);
  bool instrumentModule(Module &);
  bool instrumentEntryPoint(Module &, Function &, bool);
  bool instrumentModuleForFunction(Module &, Function &);
  std::unique_ptr<Module> generateEntryPointModule(Module &M, Function &);

private:
  Triple TargetTriple;
  std::unique_ptr<TargetLibraryInfoImpl> TLII;
  std::unique_ptr<TargetLibraryInfo> TLI;
  Function *InputGenCtorFunction = nullptr;
  InputGenInstrumenter IGI;
};

bool inputGenerationInstrumentModuleForFunction(Function &F,
                                                ModuleAnalysisManager &MAM,
                                                IGInstrumentationModeTy Mode);

} // namespace llvm

#endif
