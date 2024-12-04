//===- InputGeneration.cpp - Input generation instrumentation -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of InputGen. The idea is that we generate inputs for a
// piece of code by instrumenting it and running it once (per input) with a
// dedicated runtime. Each run yields an input (arguments and memory state) for
// the original piece of code.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/InputGeneration.h"
#include "llvm-c/Core.h"
#include "llvm/ADT/EnumeratedArray.h"
#include "llvm/ADT/STLExtras.h"
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
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DiagnosticInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/ProfDataUtils.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/ProfileData/InstrProfReader.h"
#include "llvm/Support/BLAKE3.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/HashBuilder.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/TargetParser/X86TargetParser.h"
#include "llvm/Transforms/IPO/Attributor.h"
#include "llvm/Transforms/IPO/InputGenerationImpl.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <memory>
#include <optional>
#include <string>

using namespace llvm;

#define DEBUG_TYPE "input-gen"

constexpr int LLVM_INPUT_GEN_VERSION = 1;

constexpr char VersionCheckNamePrefix[] = "version_mismatch_check_v";
constexpr char ModuleCtorName[] = "module_ctor";
constexpr char ModuleDtorName[] = "module_dtor";
constexpr char InitName[] = "init";
constexpr char DeinitName[] = "deinit";
constexpr char FilenameVar[] = "profile_filename";
static const std::string InputGenCallbackPrefix = "__inputgen_";
static const std::string InputRunCallbackPrefix = "__inputrun_";
static const std::string RecordingCallbackPrefix = "__record_";
static constexpr char OverrideFreeName[] = "__inputgen_override_free";

static std::string InputGenOutputFilename = "input_gen_%{fn}_%{uuid}.c";

static cl::opt<IGInstrumentationModeTy>
    ClInstrumentationMode("input-gen-mode", cl::desc("Instrumentation mode"),
                          cl::Hidden, cl::init(IG_Generate),
                          cl::values(clEnumValN(IG_Record, "record", ""),
                                     clEnumValN(IG_Generate, "generate", ""),
                                     clEnumValN(IG_Run, "run", "")));

static cl::opt<bool>
    ClPruneModule("input-gen-prune-module",
                  cl::desc("Prune unneeded functions from module."), cl::Hidden,
                  cl::init(true));

static cl::opt<bool> ClInsertVersionCheck(
    "input-gen-guard-against-version-mismatch",
    cl::desc("Guard against compiler/runtime version mismatch."), cl::Hidden,
    cl::init(true));

static cl::opt<std::string, true> ClOutputFilename(
    "input-gen-output-filename",
    cl::desc("Name of the file the generated input is stored in."), cl::Hidden,
    cl::location(InputGenOutputFilename));

static cl::opt<std::string>
    ClEntryPoint("input-gen-entry-point",
                 cl::desc("Entry point identification (via name or #)."),
                 cl::Hidden, cl::init("main"));

static cl::opt<bool>
    ClProvideBranchHints("input-gen-provide-branch-hints",
                         cl::desc("Provide information on values used by "
                                  "branches to the input gen runtime"),
                         cl::Hidden, cl::init(true));

static cl::opt<bool>
    ClInstrumentFunctionPtrs("input-gen-instrument-function-ptrs",
                             cl::desc("Actively handle function pointers"),
                             cl::Hidden, cl::init(true));

STATISTIC(NumInstrumented, "Number of instrumented instructions");

namespace {

// These are global variables that are never meant to be defined and are just
// used to identify types in the source language
bool isLandingPadType(GlobalVariable &GV) {
  return !GV.use_empty() && any_of(GV.uses(), [](Use &U) {
    if (isa<LandingPadInst>(U.getUser()))
      return true;
    return false;
  });
}

bool isLibCGlobal(StringRef Name) {
  return StringSwitch<bool>(Name)
      .Case("stderr", true)
      .Case("stdout", true)
      .Default(false);
}

bool isPersonalityFunction(Function &F) {
  return !F.use_empty() && all_of(F.uses(), [&](Use &U) {
    if (auto *UserF = dyn_cast<Function>(U.getUser()))
      if (UserF->getPersonalityFn() == &F)
        return true;
    return false;
  });
}

std::string getTypeName(const Type *Ty) {
  switch (Ty->getTypeID()) {
  case Type::TypeID::PointerTyID:
    return "ptr";
  case Type::TypeID::IntegerTyID:
    return "i" + to_string(Ty->getIntegerBitWidth());
  case Type::TypeID::FloatTyID:
    return "float";
  case Type::TypeID::DoubleTyID:
    return "double";
  case Type::TypeID::X86_FP80TyID:
    return "x86_fp80";
  default:
    return "unknown";
  };
}
} // end anonymous namespace

bool InputGenInstrumenter::shouldNotStubGV(GlobalVariable &GV) {
  if (isLandingPadType(GV) || isLibCGlobal(GV.getName()))
    return true;
  else if (GV.getName() == "llvm.used" || GV.getName() == "llvm.compiler.used")
    return true;
  else if (InstrumentedForCoverage && (GV.getName().starts_with("__llvm") ||
                                       GV.getName().starts_with("__prof")))
    return true;
  return false;
}

bool InputGenInstrumenter::shouldPreserveGVName(GlobalVariable &GV) {
  return shouldNotStubGV(GV);
}

bool InputGenInstrumenter::shouldNotStubFunc(StringRef Name,
                                             TargetLibraryInfo &TLI) {
  return StringSwitch<bool>(Name)
      .Case("printf", true)
      .Case("puts", true)
      .Case("malloc", true)
      .Case("calloc", true)
      .Case("__cxa_throw", true)
      .Case(OverrideFreeName, true)
      .Default(false);
}
bool InputGenInstrumenter::shouldNotStubFunc(Function &F,
                                             TargetLibraryInfo &TLI) {
  // TODO Maybe provide a way for the user to specify the allowed external
  // functions
  return shouldNotStubFunc(F.getName(), TLI);
}

bool InputGenInstrumenter::shouldPreserveFuncName(Function &F,
                                                  TargetLibraryInfo &TLI) {
  return isPersonalityFunction(F) || shouldNotStubFunc(F, TLI);
}

InputGenerationInstrumentPass::InputGenerationInstrumentPass() = default;

PreservedAnalyses
InputGenerationInstrumentPass::run(Module &M, AnalysisManager<Module> &MAM) {
  ModuleInputGenInstrumenter MIGI(M, MAM, ClInstrumentationMode, true);
  if (MIGI.instrumentClEntryPoint(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

// Instrument memset/memmove/memcpy
void InputGenInstrumenter::instrumentMemIntrinsic(MemIntrinsic *MI) {
  IRBuilder<> IRB(MI);
  IRB.SetCurrentDebugLocation(MI->getDebugLoc());
  if (isa<MemTransferInst>(MI)) {
    auto Callee = isa<MemMoveInst>(MI) ? InputGenMemmove : InputGenMemcpy;
    auto *Tgt = IRB.CreateAddrSpaceCast(MI->getOperand(0), PtrTy);
    auto *Src = IRB.CreateAddrSpaceCast(MI->getOperand(1), PtrTy);
    IRB.CreateCall(Callee, {Tgt, Src,
                            IRB.CreateZExtOrTrunc(
                                MI->getOperand(2),
                                Callee.getFunctionType()->getParamType(2))});
  } else if (isa<MemSetInst>(MI)) {
    auto *Tgt = IRB.CreateAddrSpaceCast(MI->getOperand(0), PtrTy);
    IRB.CreateCall(InputGenMemset,
                   {Tgt, MI->getOperand(1),
                    IRB.CreateZExtOrTrunc(
                        MI->getOperand(2),
                        InputGenMemset.getFunctionType()->getParamType(2))});
  }
  MI->eraseFromParent();
}

std::optional<InterestingMemoryAccess>
InputGenInstrumenter::isInterestingMemoryAccess(Instruction *I) const {
  InterestingMemoryAccess Access;
  Access.I = I;
  if (isa<MemIntrinsic>(I))
    return Access;

  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    if (IndirectionGlobalLoads.count(LI))
      return std::nullopt;
    Access.Kind = InterestingMemoryAccess::READ;
    Access.AccessTy = LI->getType();
    Access.Addr = LI->getPointerOperand();
  } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    Access.Kind = InterestingMemoryAccess::WRITE;
    Access.V = SI->getValueOperand();
    Access.AccessTy = SI->getValueOperand()->getType();
    Access.Addr = SI->getPointerOperand();
  } else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I)) {
    Access.Kind = InterestingMemoryAccess::READ_THEN_WRITE;
    Access.V = RMW->getValOperand();
    Access.AccessTy = RMW->getValOperand()->getType();
    Access.Addr = RMW->getPointerOperand();
  } else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I)) {
    Access.Kind = InterestingMemoryAccess::READ_THEN_WRITE;
    Access.V = XCHG->getCompareOperand();
    Access.AccessTy = XCHG->getCompareOperand()->getType();
    Access.Addr = XCHG->getPointerOperand();
  } else if (auto *CI = dyn_cast<CallInst>(I)) {
    auto *F = CI->getCalledFunction();
    if (F && (F->getIntrinsicID() == Intrinsic::masked_load ||
              F->getIntrinsicID() == Intrinsic::masked_store)) {
      unsigned OpOffset = 0;
      if (F->getIntrinsicID() == Intrinsic::masked_store) {
        // Masked store has an initial operand for the value.
        OpOffset = 1;
        Access.AccessTy = CI->getArgOperand(0)->getType();
        Access.V = CI->getArgOperand(0);
        Access.Kind = InterestingMemoryAccess::WRITE;
      } else {
        Access.AccessTy = CI->getType();
        Access.Kind = InterestingMemoryAccess::READ;
      }

      auto *BasePtr = CI->getOperand(0 + OpOffset);
      Access.MaybeMask = CI->getOperand(2 + OpOffset);
      Access.Addr = BasePtr;
    }
  }

  if (!Access.Addr)
    return std::nullopt;

  // For now, we simply cast our way through. This might not be the best
  // solution though. We might want to strip AS completely from the module in
  // the future. Type *PtrTy =
  // cast<PointerType>(Access.Addr->getType()->getScalarType()); if
  // (PtrTy->getPointerAddressSpace() != 0)
  //  return std::nullopt;

  // Ignore swifterror addresses.
  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.
  if (Access.Addr->isSwiftError())
    return std::nullopt;

  // Peel off GEPs and BitCasts.
  auto *Addr = Access.Addr->stripInBoundsOffsets();

  if (GlobalVariable *GV = dyn_cast<GlobalVariable>(Addr)) {
    // Do not instrument PGO counter updates.
    if (GV->hasSection()) {
      StringRef SectionName = GV->getSection();
      // Check if the global is in the PGO counters section.
      auto OF = Triple(I->getModule()->getTargetTriple()).getObjectFormat();
      if (SectionName.ends_with(
              getInstrProfSectionName(IPSK_cnts, OF, /*AddSegmentInfo=*/false)))
        return std::nullopt;
    }

    // Do not instrument accesses to LLVM internal variables.
    if (GV->getName().starts_with("__llvm"))
      return std::nullopt;
  }

  return Access;
}

void InputGenInstrumenter::instrumentUnreachable(UnreachableInst *Unreachable) {
  CallBase *NoReturnCB = nullptr;
  if (&Unreachable->getParent()->front() != Unreachable) {
    if (auto *CB = dyn_cast<CallBase>(Unreachable->getPrevNode())) {
      if (CB->hasFnAttr(Attribute::NoReturn))
        NoReturnCB = CB;
    }
  }

  IRBuilder<> IRB(Unreachable);
  Value *Name = Constant::getNullValue(PtrTy);
  if (NoReturnCB) {
    assert(NoReturnCB->getCalledFunction());
    Name = IRB.CreateGlobalString(NoReturnCB->getCalledFunction()->getName());
    NoReturnCB->eraseFromParent();
  }

  IRB.CreateCall(UnreachableCallback,
                 {IRB.getInt32(UnreachableCounter++), Name});
}

void InputGenInstrumenter::instrumentCmp(ICmpInst *Cmp) {
  Type *Ty = Cmp->getOperand(0)->getType();
  if (!Ty->isPointerTy())
    return;

  IRBuilder<> IRB(Cmp);
  auto *LHS = IRB.CreateAddrSpaceCast(Cmp->getOperand(0), PtrTy);
  auto *RHS = IRB.CreateAddrSpaceCast(Cmp->getOperand(1), PtrTy);
  IRB.CreateCall(CmpPtrCallback, {LHS, RHS, IRB.getInt32(Cmp->getPredicate())});
}

void InputGenInstrumenter::instrumentMop(
    const InterestingMemoryAccess &Access) {

  if (Access.MaybeMask)
    instrumentMaskedLoadOrStore(Access);
  else
    instrumentAddress(Access);
}

static Value *igGetUnderlyingObject(Value *Addr) {
  SmallVector<const Value *, 4> Objects;
  getUnderlyingObjects(Addr, Objects, /*LI=*/nullptr,
                       /*MaxLookup=*/12);

  Value *Object = Objects.size() == 1
                      ? const_cast<Value *>(Objects[0])
                      : getUnderlyingObject(Addr, /*MaxLookup=*/12);
  return Object;
}

void InputGenInstrumenter::instrumentMaskedLoadOrStore(
    const InterestingMemoryAccess &Access) {
  auto *CI = dyn_cast<CallInst>(Access.I);
  if (!CI)
    llvm_unreachable("Unexpected");
  auto *F = CI->getCalledFunction();
  if (!F)
    llvm_unreachable("Unexpected");
  if (!(F->getIntrinsicID() == Intrinsic::masked_load ||
        F->getIntrinsicID() == Intrinsic::masked_store))
    llvm_unreachable("Unexpected");

  Value *Object = igGetUnderlyingObject(Access.Addr);
  if (isa<AllocaInst>(Object))
    return;

  Value *Mask = nullptr;
  if (F->getIntrinsicID() == Intrinsic::masked_load)
    Mask = Access.I->getOperand(2);
  if (F->getIntrinsicID() == Intrinsic::masked_store)
    Mask = Access.I->getOperand(3);
  assert(Mask);

  auto *VT = cast<VectorType>(Access.AccessTy);
  auto *ElTy = VT->getElementType();
  auto *MaskTy = cast<VectorType>(Mask->getType());
  if (MaskTy->getElementCount().isScalable())
    llvm_unreachable("Scalable vectors unsupported.");

  SplitBlockAndInsertForEachLane(
      MaskTy->getElementCount(), IntegerType::getInt64Ty(VT->getContext()),
      Access.I, [&](IRBuilderBase &IRB, Value *Idx) {
        Value *Cond = IRB.CreateExtractElement(Mask, Idx);
        Instruction *NewTerm = SplitBlockAndInsertIfThen(
            Cond, IRB.GetInsertBlock()->getTerminator(), /*Unreachable=*/false);
        IRB.SetInsertPoint(NewTerm);
        Value *GEP = IRB.CreateGEP(Access.AccessTy, Access.Addr, {Idx});
        Value *V = nullptr;
        switch (Access.Kind) {
        case InterestingMemoryAccess::READ:
          assert(Access.V == nullptr);
          break;
        case InterestingMemoryAccess::WRITE:
          assert(Access.V != nullptr);
          V = IRB.CreateExtractElement(Access.V, Idx);
          break;
        case InterestingMemoryAccess::READ_THEN_WRITE:
          // Unimplemented, but we abort() in the runtime
          break;
        }
        int32_t AllocSize = DL->getTypeAllocSize(ElTy);
        emitMemoryAccessCallback(IRB, GEP, V, ElTy, AllocSize, Access.Kind,
                                 Object, nullptr);
      });
}

void InputGenInstrumenter::instrumentAddress(
    const InterestingMemoryAccess &Access) {
  IRBuilder<> IRB(Access.I);
  IRB.SetCurrentDebugLocation(Access.I->getDebugLoc());

  Value *Object = igGetUnderlyingObject(Access.Addr);
  if (isa_and_present<AllocaInst>(Object))
    return;
  assert(!IndirectionGlobalLoads.count(Access.I));

  std::function<void(Type *, Value *, Value *, Value *)> HandleType;
  HandleType = [&](Type *TheType, Value *TheAddr, Value *TheValue,
                   Value *ValueToReplace) {
    if (auto *ST = dyn_cast<StructType>(TheType)) {
      for (unsigned It = 0; It < ST->getNumElements(); It++) {
        Type *ElTy = ST->getElementType(It);
        auto *GEP = IRB.CreateConstGEP2_32(TheType, TheAddr, 0, It);
        Value *V = nullptr;
        switch (Access.Kind) {
        case InterestingMemoryAccess::READ:
          assert(TheValue == nullptr);
          break;
        case InterestingMemoryAccess::WRITE:
          assert(TheValue != nullptr);
          V = IRB.CreateExtractValue(TheValue, {It});
          break;
        case InterestingMemoryAccess::READ_THEN_WRITE:
          // Unimplemented, but we abort() in the runtime
          break;
        }
        HandleType(ElTy, GEP, V, nullptr);
      }
    } else if (auto *AT = dyn_cast<ArrayType>(TheType)) {
      Type *ElTy = AT->getElementType();
      for (unsigned It = 0; It < AT->getNumElements(); It++) {
        auto *GEP = IRB.CreateConstGEP2_32(TheType, TheAddr, 0, It);
        Value *V = nullptr;
        switch (Access.Kind) {
        case InterestingMemoryAccess::READ:
          assert(TheValue == nullptr);
          break;
        case InterestingMemoryAccess::WRITE:
          assert(TheValue != nullptr);
          V = IRB.CreateExtractValue(TheValue, {It});
          break;
        case InterestingMemoryAccess::READ_THEN_WRITE:
          // Unimplemented, but we abort() in the runtime
          break;
        }
        HandleType(ElTy, GEP, V, nullptr);
      }
    } else if (auto *VT = dyn_cast<VectorType>(TheType)) {
      Type *ElTy = VT->getElementType();
      if (!VT->getElementCount().isScalable()) {
        auto Count = VT->getElementCount().getFixedValue();
        for (unsigned It = 0; It < Count; It++) {
          auto *GEP = IRB.CreateConstGEP2_64(TheType, TheAddr, 0, It);
          Value *V = nullptr;
          switch (Access.Kind) {
          case InterestingMemoryAccess::READ:
            assert(TheValue == nullptr);
            break;
          case InterestingMemoryAccess::WRITE:
            assert(TheValue != nullptr);
            V = IRB.CreateExtractElement(TheValue, IRB.getInt64(It));
            break;
          case InterestingMemoryAccess::READ_THEN_WRITE:
            // Unimplemented, but we abort() in the runtime
            break;
          }
          HandleType(ElTy, GEP, V, nullptr);
        }
      } else {
        llvm_unreachable("Scalable vectors unsupported.");
      }
    } else {
      int32_t AllocSize = DL->getTypeAllocSize(TheType);
      emitMemoryAccessCallback(IRB, TheAddr, TheValue, TheType, AllocSize,
                               Access.Kind, Object, ValueToReplace);
    }
  };
  Value *ValueToReplace = nullptr;
  switch (Access.Kind) {
  case InterestingMemoryAccess::READ:
  case InterestingMemoryAccess::READ_THEN_WRITE:
    ValueToReplace = Access.I;
    break;
  case InterestingMemoryAccess::WRITE:
    ValueToReplace = nullptr;
    break;
  }
  HandleType(Access.AccessTy, Access.Addr, Access.V, ValueToReplace);
}

Value *InputGenInstrumenter::getValueForInterface(IRBuilderBase &IRB,
                                                  Value *V) {
  if (!V)
    return ConstantInt::getNullValue(Int64Ty);
  Type *AccessTy = V->getType();
  int32_t AllocSize = DL->getTypeAllocSize(AccessTy);
  // If the value cannot fit in an i64, we need to pass it by reference.
  if (AllocSize > InterfaceValueTypeSize) {
    AllocaInst *Alloca = IRB.CreateAlloca(AccessTy);
    BasicBlock &EntryBlock = IRB.GetInsertBlock()->getParent()->getEntryBlock();
    Alloca->moveBefore(EntryBlock, EntryBlock.getFirstNonPHIOrDbgOrAlloca());
    IRB.CreateStore(V, Alloca);
    return IRB.CreateBitOrPointerCast(Alloca, Int64Ty);
  } else if (AccessTy->isIntOrIntVectorTy()) {
    return IRB.CreateZExtOrTrunc(V, Int64Ty);
  } else {
    return IRB.CreateZExtOrTrunc(
        IRB.CreateBitOrPointerCast(
            V, IntegerType::get(IRB.getContext(), AllocSize * 8)),
        Int64Ty);
  }
}

void InputGenInstrumenter::emitMemoryAccessCallback(
    IRBuilderBase &IRB, Value *Addr, Value *V, Type *AccessTy,
    int32_t AllocSize, InterestingMemoryAccess::KindTy Kind, Value *Object,
    Value *ValueToReplace) {

  if (auto *GV = dyn_cast<GlobalVariable>(Addr);
      GV && isLibCGlobal(GV->getName()))
    return;

  Value *Val = getValueForInterface(IRB, V);
  auto *Ptr = IRB.CreateAddrSpaceCast(Addr, PtrTy);
  auto *Base = IRB.CreateAddrSpaceCast(Object, PtrTy);
  SmallVector<Value *, 7> Args = {Ptr, Val,
                                  ConstantInt::get(Int32Ty, AllocSize), Base,
                                  ConstantInt::get(Int32Ty, Kind)};
  auto Hints = getBranchHints(ValueToReplace, IRB);
  Args.insert(Args.end(), Hints.begin(), Hints.end());
  if (isa<PointerType>(AccessTy) && AccessTy->getPointerAddressSpace())
    AccessTy = AccessTy->getPointerTo();
  auto Fn = InputGenMemoryAccessCallback[AccessTy];
  if (!Fn.getCallee()) {
    LLVM_DEBUG(dbgs() << "No memory access callback for " << *AccessTy << "\n");
    // TODO this should be easy enough to support - just 'load' a bunch of
    // int8's
    IRB.CreateIntrinsic(VoidTy, Intrinsic::trap, {});
  } else {
    IRB.CreateCall(Fn, Args);
  }
}

static std::string getCallbackPrefix(IGInstrumentationModeTy Mode) {
  switch (Mode) {
  case IG_Run:
    return InputRunCallbackPrefix;
  case IG_Record:
    return RecordingCallbackPrefix;
  case IG_Generate:
    return InputGenCallbackPrefix;
  }
  llvm_unreachable("Invalid mode");
}

// Create the variable for the profile file name.
void createProfileFileNameVar(Module &M, Triple &TT,
                              IGInstrumentationModeTy Mode) {
  assert(!InputGenOutputFilename.empty() &&
         "Unexpected empty string for output filename");
  Constant *ProfileNameConst = ConstantDataArray::getString(
      M.getContext(), InputGenOutputFilename.c_str(), true);
  auto Prefix = getCallbackPrefix(Mode);
  GlobalVariable *ProfileNameVar = new GlobalVariable(
      M, ProfileNameConst->getType(), /*isConstant=*/true,
      GlobalValue::WeakAnyLinkage, ProfileNameConst, Prefix + FilenameVar);
  if (TT.supportsCOMDAT()) {
    ProfileNameVar->setLinkage(GlobalValue::ExternalLinkage);
    ProfileNameVar->setComdat(M.getOrInsertComdat(Prefix + FilenameVar));
  }
}

bool ModuleInputGenInstrumenter::instrumentClEntryPoint(Module &M) {
  Function *EntryPoint = M.getFunction(ClEntryPoint);
  if (!EntryPoint) {
    int No;
    if (to_integer(ClEntryPoint, No)) {
      auto It = M.begin(), End = M.end();
      while (No-- > 0 && It != End)
        It = std::next(It);
      if (It != End)
        EntryPoint = &*It;
    }
  }
  if (!EntryPoint) {
    errs() << "No entry point found, used \"" << ClEntryPoint << "\".\n";
    return false;
  }
  return instrumentModuleForFunction(M, *EntryPoint);
}

void ModuleInputGenInstrumenter::renameGlobals(Module &M,
                                               TargetLibraryInfo &TLI) {
  // Some modules define their own 'malloc' etc. or make aliases to existing
  // functions. We do not want them to override any definition that we depend
  // on in our runtime, thus, rename all globals.
  auto Rename = [](auto &S) {
    if (!S.isDeclaration())
      S.setName("__inputgen_renamed_" + S.getName());
  };
  for (auto &X : M.globals()) {
    X.setComdat(nullptr);
    if (IGI.shouldPreserveGVName(X))
      continue;
    if (X.getValueType()->isSized())
      X.setLinkage(GlobalVariable::InternalLinkage);
    Rename(X);
  }
  for (auto &X : M.functions()) {
    X.setComdat(nullptr);
    if (IGI.shouldPreserveFuncName(X, TLI))
      continue;
    Rename(X);
  }
  for (auto &X : M.ifuncs()) {
    X.setComdat(nullptr);
    Rename(X);
  }
  for (auto &X : M.aliases())
    Rename(X);
}

bool ModuleInputGenInstrumenter::instrumentModule(Module &M) {

  IGI.initializeCallbacks(M);

  switch (IGI.Mode) {
  case IG_Run:
  case IG_Generate:
    IGI.declareProbeStackFuncs(M);

    if (Function *Free = M.getFunction("free"))
      Free->setName(OverrideFreeName);

    IGI.removeTokenFunctions(M);
    if (ClInstrumentFunctionPtrs)
      IGI.gatherFunctionPtrCallees(M);

    break;
  case IG_Record:
    break;
  }

  switch (IGI.Mode) {
  case IG_Run:
    IGI.provideGlobals(M);
    renameGlobals(M, *TLI);
    IGI.handleUnreachable(M);
    break;
  case IG_Generate:
    IGI.provideGlobals(M);
    renameGlobals(M, *TLI);
    LLVM_FALLTHROUGH;
  case IG_Record:
    for (auto &Fn : M)
      if (!Fn.isDeclaration())
        IGI.instrumentFunction(Fn);
    break;
  }

  switch (IGI.Mode) {
  case IG_Run:
  case IG_Record:
    break;
  case IG_Generate:
    auto Prefix = getCallbackPrefix(IGI.Mode);

    // Create a module constructor.
    std::string InputGenVersion = std::to_string(LLVM_INPUT_GEN_VERSION);
    std::string VersionCheckName =
        ClInsertVersionCheck
            ? (Prefix + VersionCheckNamePrefix + InputGenVersion)
            : "";
    std::tie(InputGenCtorFunction, std::ignore) =
        createSanitizerCtorAndInitFunctions(M, Prefix + ModuleCtorName,
                                            Prefix + InitName,
                                            /*InitArgTypes=*/{},
                                            /*InitArgs=*/{}, VersionCheckName);

    appendToGlobalCtors(M, InputGenCtorFunction, /*Priority=*/1);

    FunctionType *FnTy = FunctionType::get(IGI.VoidTy, false);
    auto *DeinitFn = Function::Create(FnTy, GlobalValue::InternalLinkage,
                                      Prefix + ModuleDtorName, M);
    auto *EntryBB = BasicBlock::Create(*IGI.Ctx, "entry", DeinitFn);
    FunctionCallee DeinitBody = M.getOrInsertFunction(
        Prefix + DeinitName, FunctionType::get(IGI.VoidTy, false));
    CallInst::Create(DeinitBody, "", EntryBB);
    ReturnInst::Create(*IGI.Ctx, EntryBB);

    appendToGlobalDtors(M, DeinitFn, /*Priority=*/1000);

    ::createProfileFileNameVar(M, TargetTriple, IGI.Mode);
  }

  switch (IGI.Mode) {
  case IG_Record:
    break;
  case IG_Run:
  case IG_Generate:
    IGI.stubDeclarations(M, *TLI);

    auto *GlobalInitF =
        Function::Create(FunctionType::get(IGI.VoidTy, /*isVarArg=*/false),
                         GlobalValue::ExternalLinkage, "__input_gen_init", &M);
    auto *EntryBB =
        BasicBlock::Create(GlobalInitF->getContext(), "entry", GlobalInitF);
    IRBuilder<> IRB(EntryBB);
    IGI.createGlobalCalls(M, IRB);
    IRB.CreateRetVoid();
  }

  return true;
}

bool ModuleInputGenInstrumenter::instrumentEntryPoint(Module &M,
                                                      Function &EntryPoint,
                                                      bool UniqName) {
  EntryPoint.setLinkage(GlobalValue::ExternalLinkage);

  switch (IGI.Mode) {
  case IG_Record:
    IGI.createRecordingEntryPoint(EntryPoint);
    break;
  case IG_Generate:
    IGI.createGenerationEntryPoint(EntryPoint, UniqName);
    break;
  case IG_Run:
    IGI.createRunEntryPoint(EntryPoint, UniqName);
    break;
  }

  return true;
}

bool ModuleInputGenInstrumenter::instrumentModuleForFunction(
    Module &M, Function &EntryPoint) {
  if (EntryPoint.isDeclaration()) {
    errs() << "Entry point is declaration, used \"" << EntryPoint.getName()
           << "\".\n";
    return false;
  }

  switch (IGI.Mode) {
  case IG_Generate:
  case IG_Run:
    IGI.pruneModule(EntryPoint);
    instrumentModule(M);
    instrumentEntryPoint(M, EntryPoint, /*UniqName=*/false);
    instrumentFunctionPtrs(M);
    break;
  case IG_Record:
    instrumentModule(M);
    instrumentEntryPoint(M, EntryPoint, /*UniqName=*/false);
    break;
  }

  return true;
}

bool ModuleInputGenInstrumenter::instrumentFunctionPtrs(Module &M) {
  if (ClInstrumentFunctionPtrs)
    IGI.instrumentFunctionPtrSources(M);
  IGI.provideFunctionPtrGlobals(M);

  return true;
}

// We need to declare the probe stack functions as they may need to be stubbed.
// They may only be materialized in later passes and we may miss them otherwise.
void InputGenInstrumenter::declareProbeStackFuncs(Module &M) {
  SmallSetVector<StringRef, 1> ToAdd;
  auto AddName = [&](StringRef Name, auto Callback) {
    // Not a function name
    if (Name == "inline_asm")
      return;
    if (!shouldNotStubFunc(Name, TLI)) {
      if (!M.getFunction(Name))
        ToAdd.insert(Name);
      Callback();
    }
  };
  if (const auto *PS =
          dyn_cast_or_null<MDString>(M.getModuleFlag("probe-stack"))) {
    auto Name = PS->getString();
    AddName(Name, [&]() {
      Metadata *Val = MDString::get(
          M.getContext(),
          std::string("__inputgen_renamed_" + Name.str()).c_str());
      M.setModuleFlag(Module::ModFlagBehavior::Override, "probe-stack", Val);
    });
  }
  for (Function &F : M) {
    if (!F.hasFnAttribute("probe-stack"))
      continue;

    auto Attr = F.getFnAttribute("probe-stack");
    auto Name = Attr.getValueAsString();
    AddName(Name, [&]() {
      F.addFnAttr("probe-stack",
                  std::string("__inputgen_renamed_" + Name.str()).c_str());
    });
  }

  SmallVector<GlobalValue *, 1> Added;
  for (auto Name : ToAdd)
    Added.push_back(
        cast<Function>(M.getOrInsertFunction(
                            Name, FunctionType::get(VoidTy, /*isVarArg=*/false))
                           .getCallee()));
  appendToUsed(M, Added);
}

void InputGenInstrumenter::initializeCallbacks(Module &M) {

  auto Prefix = getCallbackPrefix(Mode);

  Type *Types[] = {Int1Ty,   Int8Ty, Int16Ty, Int32Ty,  Int64Ty,
                   Int128Ty, PtrTy,  FloatTy, DoubleTy, X86_FP80Ty};
  for (Type *Ty : Types) {
    InputGenMemoryAccessCallback[Ty] = M.getOrInsertFunction(
        Prefix + "access_" + ::getTypeName(Ty), VoidTy, PtrTy, Int64Ty, Int32Ty,
        PtrTy, Int32Ty, PtrTy, Int32Ty);
    StubValueGenCallback[Ty] = M.getOrInsertFunction(
        Prefix + "stub_" + ::getTypeName(Ty), Ty, PtrTy, Int32Ty);
    ArgGenCallback[Ty] = M.getOrInsertFunction(
        Prefix + "arg_" + ::getTypeName(Ty), Ty, PtrTy, Int32Ty);
    ArgRecordCallback[Ty] =
        M.getOrInsertFunction(Prefix + "arg_record_" + ::getTypeName(Ty),
                              VoidTy, Int64Ty, PtrTy, Int32Ty);
  }

  InputGenMemmove =
      M.getOrInsertFunction(Prefix + "memmove", PtrTy, PtrTy, PtrTy, Int64Ty);
  InputGenMemcpy =
      M.getOrInsertFunction(Prefix + "memcpy", PtrTy, PtrTy, PtrTy, Int64Ty);
  InputGenMemset =
      M.getOrInsertFunction(Prefix + "memset", PtrTy, PtrTy, Int8Ty, Int64Ty);
  UseCallback = M.getOrInsertFunction(Prefix + "use", VoidTy, PtrTy, Int32Ty);
  CmpPtrCallback =
      M.getOrInsertFunction(Prefix + "cmp_ptr", VoidTy, PtrTy, PtrTy, Int32Ty);
  UnreachableCallback =
      M.getOrInsertFunction(Prefix + "unreachable", VoidTy, Int32Ty, PtrTy);
}

void InputGenInstrumenter::collectABIInfo(CallBase &CB,
                                          SmallVector<ABIAttrs> &ABIInfo) {
  for (unsigned I = 0; I < CB.arg_size(); ++I) {
    Type *StructRet = CB.getParamStructRetType(I);
    Type *InAlloca = CB.getParamInAllocaType(I);
    Type *ByVal = CB.getParamByValType(I);
    bool SwiftSelf = CB.getParamAttr(I, Attribute::SwiftSelf).isValid();
    ABIInfo.push_back({StructRet, InAlloca, ByVal, SwiftSelf});
  }
}
void InputGenInstrumenter::collectABIInfo(Function &F,
                                          SmallVector<ABIAttrs> &ABIInfo) {
  for (unsigned I = 0; I < F.arg_size(); ++I) {
    Type *StructRet = F.getParamStructRetType(I);
    Type *InAlloca = F.getParamInAllocaType(I);
    Type *ByVal = F.getParamByValType(I);
    bool SwiftSelf = F.getParamAttribute(I, Attribute::SwiftSelf).isValid();
    ABIInfo.push_back({StructRet, InAlloca, ByVal, SwiftSelf});
  }
}
template <typename TY>
void InputGenInstrumenter::setABIInfo(TY &CorF,
                                      const SmallVector<ABIAttrs> &ABIInfo,
                                      IRBuilder<> &IRB) {
  auto DL = M.getDataLayout();
  auto &Ctx = CorF.getContext();
  int Idx = 0;
  for (auto &ArgInfo : ABIInfo) {
    Type *Ty = nullptr;
    if (ArgInfo.StructRet) {
      CorF.addParamAttr(
          Idx, Attribute::getWithStructRetType(Ctx, ArgInfo.StructRet));
      Ty = ArgInfo.StructRet;
    }
    if (ArgInfo.InAlloca) {
      CorF.addParamAttr(Idx,
                        Attribute::getWithInAllocaType(Ctx, ArgInfo.InAlloca));
      Ty = ArgInfo.InAlloca;
    }
    if (ArgInfo.ByVal) {
      CorF.addParamAttr(Idx, Attribute::getWithByValType(Ctx, ArgInfo.ByVal));
      Ty = ArgInfo.ByVal;
    }
    if (ArgInfo.SwiftSelf)
      CorF.addParamAttr(Idx, Attribute::SwiftSelf);
    if (Ty && Mode == IGInstrumentationModeTy::IG_Generate) {
      Value *Addr = nullptr;
      if constexpr (std::is_same<TY, Function>::value) {
        Addr = CorF.getArg(Idx);
      } else if constexpr (std::is_same<TY, CallInst>::value) {
        Addr = CorF.getArgOperand(Idx);
      } else {
        llvm_unreachable("Unhandled type");
      }
      InterestingMemoryAccess IMA = {
          &*IRB.GetInsertPoint(),       Addr, Ty, nullptr, nullptr,
          InterestingMemoryAccess::READ};
      instrumentMop(IMA);
    }
    ++Idx;
  }
}

Function &InputGenInstrumenter::createFunctionPtrStub(Module &M, CallBase &CB) {
  auto *FT = CB.getFunctionType();
  SmallVector<ABIAttrs> ABIInfo;
  collectABIInfo(CB, ABIInfo);
  auto IsEquivalentStub = [&](Function &F) {
    if (F.getFunctionType() != FT ||
        !F.getName().starts_with("__inputgen_fpstub_") ||
        F.getCallingConv() != CB.getCallingConv())
      return false;

    SmallVector<ABIAttrs> FnABIInfo;
    collectABIInfo(F, FnABIInfo);
    return ABIInfo == FnABIInfo;
  };
  if (auto It = find_if(M, IsEquivalentStub); It != M.end())
    return *It;
  auto *F = Function::Create(
      FT, GlobalValue::WeakAnyLinkage,
      "__inputgen_fpstub_" + std::to_string(StubNameCounter++), M);
  F->setCallingConv(CB.getCallingConv());
  stubDeclaration(M, *F);
  IRBuilder<> IRB(
      &F->getEntryBlock(),
      F->getEntryBlock().getFirstNonPHIOrDbgOrAlloca()->getIterator());
  setABIInfo(*F, ABIInfo, IRB);
  return *F;
}

void InputGenInstrumenter::stubDeclaration(Module &M, Function &F) {
  F.setLinkage(GlobalValue::WeakAnyLinkage);
  F.setMetadata(LLVMContext::MD_dbg, nullptr);

  auto *EntryBB = BasicBlock::Create(*Ctx, "entry", &F);

  IRBuilder<> IRB(EntryBB);
  auto *RTy = F.getReturnType();
  if (RTy->isVoidTy())
    IRB.CreateRetVoid();
  else
    IRB.CreateRet(constructTypeUsingCallbacks(M, IRB, StubValueGenCallback, RTy,
                                              nullptr, nullptr));

  if (RTy->isVoidTy())
    return;
  if (!ClProvideBranchHints)
    return;

  // To generate branch hints we need to generate the value at the call site
  // scope.
  // TODO We can make this work for Invoke too but it is slightly more annoying
  SmallVector<CallInst *> ToStub;
  for (auto *User : F.users())
    if (auto *CI = dyn_cast<CallInst>(User))
      if (CI->getCalledFunction() == &F)
        ToStub.push_back(CI);
  for (auto *CI : ToStub) {
    // TODO we may want to simulate throwing in stubs. We would need to tweak
    // this in that case.
    IRBuilder<> IRB(CI);
    Value *V = constructTypeUsingCallbacks(M, IRB, StubValueGenCallback, RTy,
                                           CI, nullptr);
    CI->replaceAllUsesWith(V);
    CI->eraseFromParent();
  }
}

void InputGenInstrumenter::stubDeclarations(Module &M, TargetLibraryInfo &TLI) {
  auto Prefix = getCallbackPrefix(Mode);

  for (Function &F : M) {
    if (!F.isDeclaration()) {
      F.setLinkage(GlobalValue::InternalLinkage);
      continue;
    }

    if (F.isIntrinsic())
      continue;

    if (F.getName().starts_with(Prefix))
      continue;

    if (shouldNotStubFunc(F, TLI))
      continue;

    if (!shouldPreserveFuncName(F, TLI))
      F.setName("__inputgen_renamed_" + F.getName());
    stubDeclaration(M, F);
  }
}

void InputGenInstrumenter::removeTokenFunctions(Module &M) {
  auto RemoveFn = [&](Function &Fn) {
    while (!Fn.user_empty()) {
      auto *I = cast<Instruction>(Fn.user_back());
      if (I->getType()->isTokenTy()) {
        while (!I->user_empty()) {
          auto *UI = cast<Instruction>(I->user_back());
          UI->eraseFromParent();
        }
      }
      I->replaceAllUsesWith(UndefValue::get(I->getType()));
      I->eraseFromParent();
    }
  };

  for (auto &Fn : M) {
    if (!Fn.isDeclaration())
      continue;
    if (Fn.getReturnType()->isTokenTy()) {
      RemoveFn(Fn);
      continue;
    }
    for (auto &Arg : Fn.args())
      if (Arg.getType()->isTokenTy()) {
        RemoveFn(Fn);
        break;
      }
  }
}

void InputGenInstrumenter::gatherFunctionPtrCallees(Module &M) {
  SetVector<CallBase *> Calls;

  FunctionAnalysisManager &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  AnalysisGetter AG(FAM, /* CachedOnly */ false);

  CallGraphUpdater CGUpdater;
  BumpPtrAllocator Allocator;
  InformationCache InfoCache(M, AG, Allocator, nullptr);

  SetVector<Function *> Functions;
  for (Function &F : M)
    Functions.insert(&F);

  DenseSet<const char *> Allowed({&AAIndirectCallInfo::ID});

  AttributorConfig AC(CGUpdater);
  AC.IsModulePass = true;
  AC.DeleteFns = false;
  AC.Allowed = &Allowed;
  AC.UseLiveness = false;
  AC.DefaultInitializeLiveInternals = false;
  AC.IsClosedWorldModule = true;
  AC.InitializationCallback = [&Calls](Attributor &A, const Function &F) {
    for (auto &I : instructions(F)) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (CB->isIndirectCall()) {
          // Insert the CB
          A.getOrCreateAAFor<AAIndirectCallInfo>(
              IRPosition::callsite_function(*CB));
          Calls.insert(const_cast<CallBase *>(CB));
        }
      }
    }
  };
  AC.IndirectCalleeSpecializationCallback =
      [&](Attributor &, const AbstractAttribute &AA, CallBase &CB,
          Function &Callee) { return false; };

  Attributor A(Functions, InfoCache, AC);
  for (Function &F : M)
    AC.InitializationCallback(A, F);
  A.run();

  auto ArgAlreadyCB = [](Function &F, uint64_t ArgNo) {
    if (auto *CallbacksMD = F.getMetadata(LLVMContext::MD_callback)) {
      if (auto *ExistingCallbacks = dyn_cast<MDTuple>(CallbacksMD)) {
        for (auto &ExistingCB : ExistingCallbacks->operands()) {
          auto *ExistingCBIdxAsCM =
              cast<ConstantAsMetadata>(cast<MDNode>(ExistingCB)->getOperand(0));
          auto ExistingCBIdx =
              cast<ConstantInt>(ExistingCBIdxAsCM->getValue())->getZExtValue();
          if (ExistingCBIdx == ArgNo)
            return true;
        }
      }
    }
    return false;
  };

  auto CandidatesFromCalleeMD = [&](CallBase &CB) {
    SmallVector<Function *> Callees;
    if (auto *CalleesMD = CB.getMetadata(LLVMContext::MD_callees)) {
      for (auto &CalleeMD : CalleesMD->operands()) {
        auto *CalleeAsVMD = cast<ValueAsMetadata>(CalleeMD)->getValue();
        auto *Callee = cast<Function>(CalleeAsVMD);
        if (CB.getFunctionType() == Callee->getFunctionType() &&
            CB.getFunction() != Callee) {
          SmallVector<ABIAttrs> CBABIInfo, FnABIInfo;
          collectABIInfo(*Callee, FnABIInfo);
          collectABIInfo(CB, CBABIInfo);
          if (CBABIInfo == FnABIInfo)
            Callees.push_back(Callee);
        }
      }
    }
    return Callees;
  };

  for (auto *Call : Calls) {
    auto *F = Call->getFunction();
    LLVM_DEBUG(dbgs() << *Call << " in function " << F->getName() << "\n");

    auto Candidates = CandidatesFromCalleeMD(*Call);

    for (auto *Candidate : Candidates) {
      LLVM_DEBUG(dbgs() << "    " << Candidate->getName() << '\n');
    }

    Candidates.push_back(&createFunctionPtrStub(M, *Call));

    MDBuilder Builder(F->getContext());
    auto *FilteredCallees = Builder.createCallees(Candidates);
    Call->setMetadata(LLVMContext::MD_callees, FilteredCallees);

    // todo: well, this only works if the argument is directly called, not
    // there's casts and so on inbetween..
    if (auto *Arg = dyn_cast<Argument>(Call->getCalledOperand())) {
      if (ArgAlreadyCB(*F, Arg->getArgNo()))
        continue;

      MDBuilder Builder(Arg->getContext());
      SmallVector<int> Ops(Call->getNumOperands() - 1, -1);
      for (std::size_t I = 0; I < Ops.size(); ++I) {
        if (auto *OpArg = dyn_cast<Argument>(Call->getOperand(I)))
          Ops[I] = OpArg->getArgNo();
        // Todo: verify if we need to comply with the non inspection and
        // check if the arg has any other uses in this function.
      }
      auto *NewCallback = Builder.createCallbackEncoding(
          Arg->getArgNo(), Ops, Call->getFunctionType()->isVarArg());
      if (auto *ExistingCallbacks = F->getMetadata(LLVMContext::MD_callback)) {
        NewCallback =
            Builder.mergeCallbackEncodings(ExistingCallbacks, NewCallback);
      } else {
        NewCallback = MDNode::get(F->getContext(), {NewCallback});
      }
      F->setMetadata(LLVMContext::MD_callback, NewCallback);
    }
  }
}

void InputGenInstrumenter::instrumentFunctionPtrSources(Module &M) {

  FunctionAnalysisManager &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  AnalysisGetter AG(FAM, /* CachedOnly */ false);

  CallGraphUpdater CGUpdater;
  BumpPtrAllocator Allocator;
  InformationCache InfoCache(M, AG, Allocator, nullptr);

  SetVector<Function *> Functions;
  for (Function &F : M)
    Functions.insert(&F);

  // clang-format off
  DenseSet<const char *> Allowed({
      &AAPotentialValues::ID,
      &AACallEdges::ID,
      &AAGlobalValueInfo::ID,
      &AAIndirectCallInfo::ID,
      &AAInstanceInfo::ID,
      &AAInterFnReachability::ID,
      &AAIntraFnReachability::ID,
      // &AAIsDead::ID, // this kills insts that are still referred to by the
      // getAssumedSimplifiedValues lookup..
      &AAMemoryBehavior::ID,
      &AAMemoryLocation::ID,
      &AANoCapture::ID,
      &AANonNull::ID,
      &AANoRecurse::ID,
      &AANoReturn::ID,
      &AANoSync::ID,
      &AAPointerInfo::ID,
      &AAPotentialConstantValues::ID,
      &AAUnderlyingObjects::ID,
      &AAValueConstantRange::ID,
  });
  // clang-format on

  AttributorConfig AC(CGUpdater);
  AC.IsModulePass = true;
  AC.DeleteFns = false;
  AC.Allowed = &Allowed;
  AC.UseLiveness = false;
  AC.DefaultInitializeLiveInternals = false;
  AC.IsClosedWorldModule = true;
  AC.InitializationCallback = [](Attributor &A, const Function &F) {
    for (auto &I : instructions(F)) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        if (CB->isIndirectCall()) {
          A.getOrCreateAAFor<AAPotentialValues>(
              IRPosition::value(*CB->getCalledOperand(), CB));
          LLVM_DEBUG(dbgs() << "CB: " << *CB << " in "
                            << CB->getCaller()->getName() << '\n');
        }
      }
    }
  };
  AC.IndirectCalleeSpecializationCallback =
      [&](Attributor &, const AbstractAttribute &AA, CallBase &CB,
          Function &Callee) { return false; };
  AC.IPOAmendableCB = [](const Function &F) {
    return !F.isDeclaration() || F.hasWeakAnyLinkage();
  };

  Attributor A(Functions, InfoCache, AC);
  for (Function &F : M)
    AC.InitializationCallback(A, F);
  A.run();

  SetVector<const CallBase *> IndirectCIs;
  ValueToValueMapTy VMap;
  SetVector<Instruction *> ToDelete;
  for (auto &F : M)
    for (auto &I : instructions(F))
      if (auto *CI = dyn_cast<CallBase>(&I); CI && CI->isIndirectCall())
        IndirectCIs.insert(CI);
  for (auto *Call : IndirectCIs) {
    auto *F = Call->getFunction();
    LLVM_DEBUG(dbgs() << *Call << " in function " << F->getName() << "\n");

    SmallVector<AA::ValueAndContext> Values;
    bool UsedAssumedInformation = false;

    if (A.getAssumedSimplifiedValues(
            IRPosition::value(*Call->getCalledOperand(), Call), nullptr, Values,
            AA::ValueScope::AnyScope, UsedAssumedInformation)) {
      for (auto &VAC : Values) {
        auto *V = VAC.getValue();
        LLVM_DEBUG(dbgs() << "Value ";
                   if (isa<Function>(V)) dbgs() << V->getName();
                   else dbgs() << *V;
                   if (VAC.getCtxI()) dbgs() << " and inst " << *VAC.getCtxI();
                   dbgs() << '\n');

        if (isa<Function>(V) || isa<UndefValue>(V) || isa<Constant>(V) ||
            isa<ConstantPointerNull>(V) || VMap.lookup(V))
          continue;

        // don't need to rewrite arguments here, as we already have them handled
        // in the entry point.
        if (isa<Argument>(V))
          continue;

        auto *IP = [CtxI = VAC.getCtxI(), V]() {
          if (auto *I = dyn_cast<Instruction>(V))
            return I;
          return const_cast<Instruction *>(CtxI);
        }();
        assert(IP && "must have a valid IP!");
        IRBuilder<> IRB(IP);
        if (auto *NewV =
                constructFpFromPotentialCallees(*Call, *V, IRB, ToDelete)) {
          V->replaceAllUsesWith(NewV);
          auto *VI = dyn_cast<Instruction>(V);
          // Leave invoke insts intact for now. TODO once we start simulating
          // throwing we should tweak this
          if (VI && !isa<InvokeInst>(VI))
            ToDelete.insert(VI);
        }
      }
    }
  }

  for (auto *VI : ToDelete)
    VI->eraseFromParent();
}

void InputGenInstrumenter::provideFunctionPtrGlobals(Module &M) {
  // insert global list of all functions to be used for identifying FPs in
  // objects.
  SmallVector<Constant *> FuncVec;
  for (auto &F : M) {
    if (F.getName().starts_with("__inputgen_renamed") ||
        F.getName().starts_with("__inputgen_fpstub"))
      FuncVec.push_back(&F);
  }
  sort(FuncVec, [](const Constant *LHS, const Constant *RHS) {
    return LHS->getName() < RHS->getName();
  });
  auto *ArrTy =
      ArrayType::get(PointerType::getUnqual(M.getContext()), FuncVec.size());
  auto *CalleeArr = ConstantArray::get(ArrTy, FuncVec);

  auto *CalleeGV =
      new GlobalVariable(ArrTy, true, GlobalValue::ExternalLinkage, CalleeArr,
                         getCallbackPrefix(Mode) + "function_pointers");
  M.insertGlobalVariable(CalleeGV);
  auto *Int32Ty = IntegerType::get(M.getContext(), 32);
  M.insertGlobalVariable(
      new GlobalVariable(Int32Ty, true, GlobalValue::ExternalLinkage,
                         ConstantInt::get(Int32Ty, FuncVec.size()),
                         getCallbackPrefix(Mode) + "num_function_pointers"));
}

void InputGenInstrumenter::provideGlobals(Module &M) {
  // Erase global c/dtors
  auto Erase = [&](StringRef Name) {
    if (GlobalVariable *GV = M.getNamedGlobal(Name))
      GV->eraseFromParent();
  };
  Erase("llvm.global_ctors");
  Erase("llvm.global_dtors");

  for (GlobalVariable &GV : M.globals()) {
    if (isLandingPadType(GV)) {
      GV.setLinkage(GlobalValue::WeakAnyLinkage);
      GV.setInitializer(Constant::getNullValue(GV.getValueType()));
      continue;
    }
    if (shouldNotStubGV(GV))
      continue;
    if (!GV.getValueType()->isSized()) {
      assert(GV.hasExternalLinkage());
      GV.setLinkage(GlobalValue::ExternalWeakLinkage);
      continue;
    }
    if (!GV.isConstant())
      MaybeExtInitializedGlobals.push_back({&GV, nullptr});
    if (!GV.hasExternalLinkage())
      continue;
    GV.setConstant(false);
    GV.setLinkage(GlobalValue::WeakAnyLinkage);
    GV.setInitializer(Constant::getNullValue(GV.getValueType()));
  }

  if (Mode != IG_Generate)
    return;

  // Code that introduces an indirection for globals.
  SmallVector<Use *> InstUses;
  for (auto &It : MaybeExtInitializedGlobals) {
    auto &GV = *It.first;
    auto &GVPtr = *new GlobalVariable(
        GV.getType(), false, GlobalValue::PrivateLinkage,
        Constant::getNullValue(GV.getType()), GV.getName() + ".ptr");
    It.second = &GVPtr;
    M.insertGlobalVariable(&GVPtr);
    InstUses.clear();
    for (auto &U : GV.uses())
      if (isa<Instruction>(U.getUser()))
        InstUses.push_back(&U);
    DenseMap<Function *, Value *> FnMap;
    for (auto &U : make_pointee_range(InstUses)) {
      Instruction *UserI = cast<Instruction>(U.getUser());
      Value *&ReplVal = FnMap[UserI->getFunction()];
      if (!ReplVal) {
        ReplVal = new LoadInst(
            GV.getType(), &GVPtr, GV.getName() + ".reload",
            UserI->getFunction()->getEntryBlock().getFirstInsertionPt());
        IndirectionGlobalLoads.insert(ReplVal);
      }
      U.set(ReplVal);
    }
  }
}

SetVector<Function *> InputGenInstrumenter::pruneModule(Function &F) {
  Module &M = *F.getParent();
  SetVector<Function *> Functions;
  Functions.insert(&F);
  for (Function &Fn : M) {
    if (&Fn == &F || Fn.isDeclaration())
      continue;

    Functions.insert(&Fn);
  }

  FunctionAnalysisManager &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  AnalysisGetter AG(FAM, /* CachedOnly */ false);

  CallGraphUpdater CGUpdater;
  BumpPtrAllocator Allocator;
  InformationCache InfoCache(M, AG, Allocator, nullptr);
  for (Function &F : M)
    Functions.insert(&F);

  AttributorConfig AC(CGUpdater);
  AC.IsModulePass = true;
  AC.DeleteFns = true;
  AC.Allowed = nullptr;
  AC.UseLiveness = true;
  AC.DefaultInitializeLiveInternals = false;
  AC.InitializationCallback = [](Attributor &A, const Function &F) {
    A.getOrCreateAAFor<AAIsDead>(IRPosition::function(F), nullptr,
                                 DepClassTy::OPTIONAL);
    for (auto &Arg : F.args()) {
      if (Arg.getType()->isPointerTy())
        A.getOrCreateAAFor<AAMemoryBehavior>(IRPosition::argument(Arg), nullptr,
                                             DepClassTy::OPTIONAL);
    }
  };

  Attributor A(Functions, InfoCache, AC);
  for (Function &F : M)
    AC.InitializationCallback(A, F);

  A.run();

  return Functions;
}

void InputGenInstrumenter::instrumentModuleForEntryPoint(Function &F) {

  auto Functions = pruneModule(F);

  for (auto *Fn : Functions)
    if (!Fn->isDeclaration())
      instrumentFunction(*Fn);
}

void InputGenInstrumenter::createRecordingEntryPoint(Function &F) {
  Module &M = *F.getParent();
  IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
  IRB.SetCurrentDebugLocation(F.getEntryBlock().getTerminator()->getDebugLoc());

  FunctionCallee PushFn = M.getOrInsertFunction(
      getCallbackPrefix(Mode) + "push", FunctionType::get(VoidTy, false));
  IRB.CreateCall(PushFn, {});

  for (auto &Arg : F.args())
    recordValueUsingCallbacks(M, IRB, ArgRecordCallback, &Arg);

  FunctionCallee PopFn = M.getOrInsertFunction(
      getCallbackPrefix(Mode) + "pop", FunctionType::get(VoidTy, false));
  for (auto &I : instructions(F)) {
    if (!isa<ReturnInst>(I))
      continue;
    IRB.SetInsertPoint(&I);
    IRB.SetCurrentDebugLocation(I.getDebugLoc());
    IRB.CreateCall(PopFn, {});
  }
}

void InputGenInstrumenter::createGlobalCalls(Module &M, IRBuilder<> &IRB) {
  FunctionCallee GVFn = M.getOrInsertFunction(
      getCallbackPrefix(Mode) + "global",
      FunctionType::get(VoidTy, {Int32Ty, PtrTy, PtrTy, Int32Ty}, false));

  auto *NumGlobalsVal =
      ConstantInt::get(Int32Ty, MaybeExtInitializedGlobals.size());
  for (auto &It : MaybeExtInitializedGlobals) {
    auto *GV = It.first;
    auto *GVPtr = It.second ? It.second : Constant::getNullValue(PtrTy);
    auto GVSize = DL->getTypeAllocSize(GV->getValueType());
    IRB.CreateCall(
        GVFn, {NumGlobalsVal, GV, GVPtr, ConstantInt::get(Int32Ty, GVSize)});
  }
}

using BranchHint = inputgen::BranchHint;
struct BranchHintInfo {
  BranchHint BH;
  BasicBlock *BB;
};

static void findAllBranchValues(Value *V,
                                SmallVector<BranchHintInfo> &BranchHints,
                                std::function<bool(Value *)> DominatesCallback,
                                const BlockFrequencyInfo &BFI) {
  auto GetBlockProfileCount = [&](Instruction &I, uint32_t Idx) -> uint64_t {
    SmallVector<uint32_t> Weights;
    if (isa<UnreachableInst>(I.getSuccessor(Idx)->getTerminator()))
      return 100UL;
    if (!extractBranchWeights(I, Weights))
      return 0UL;
    if (Weights.size() <= Idx)
      return 0UL;
    return Weights[Idx];
  };
  for (auto *U : V->users()) {
    if (auto *BI = dyn_cast<BranchInst>(U)) {
      auto *Cond = BI->getCondition();
      assert(Cond == V);
      BranchHint BHTrue = {BranchHint::EQ, true,
                           ConstantInt::get(Cond->getType(), 1),
                           GetBlockProfileCount(*BI, 0), -1};
      BranchHint BHFalse = {BranchHint::NE, true,
                            ConstantInt::get(Cond->getType(), 1),
                            GetBlockProfileCount(*BI, 1), -1};
      BranchHints.push_back({BHTrue, BI->getSuccessor(0)});
      BranchHints.push_back({BHFalse, BI->getSuccessor(1)});
    } else if (auto *Cmp = dyn_cast<CmpInst>(U)) {
      auto *LHS = Cmp->getOperand(0);
      auto *RHS = Cmp->getOperand(1);
      Value *Other;
      if (V == LHS)
        Other = RHS;
      else if (V == RHS)
        Other = LHS;
      else
        llvm_unreachable("???");

      BranchHint::KindTy Kind = BranchHint::Invalid;
      bool Signed = true;

      auto GetNegated = [](BranchHint::KindTy Kind) {
        switch (Kind) {
        case BranchHint::EQ:
          return BranchHint::NE;
        case BranchHint::NE:
          return BranchHint::EQ;
        case BranchHint::LT:
          return BranchHint::GE;
        case BranchHint::GT:
          return BranchHint::LE;
        case BranchHint::LE:
          return BranchHint::GT;
        case BranchHint::GE:
          return BranchHint::LT;
        case BranchHint::Invalid:
          return BranchHint::Invalid;
        };
      };

      switch (Cmp->getPredicate()) {
      case CmpInst::FCMP_OEQ:
      case CmpInst::FCMP_UEQ:
      case CmpInst::ICMP_EQ:
        Kind = BranchHint::EQ;
        break;
      case CmpInst::FCMP_OGT:
      case CmpInst::FCMP_UGT:
      case CmpInst::ICMP_UGT:
        Signed = false;
        [[fallthrough]];
      case CmpInst::ICMP_SGT:
        Kind = BranchHint::GT;
        break;
      case CmpInst::FCMP_OGE:
      case CmpInst::FCMP_UGE:
      case CmpInst::ICMP_UGE:
        Signed = false;
        [[fallthrough]];
      case CmpInst::ICMP_SGE:
        Kind = BranchHint::GE;
        break;
      case CmpInst::FCMP_OLT:
      case CmpInst::FCMP_ULT:
      case CmpInst::ICMP_ULT:
        Signed = false;
        [[fallthrough]];
      case CmpInst::ICMP_SLT:
        Kind = BranchHint::LT;
        break;
      case CmpInst::FCMP_OLE:
      case CmpInst::FCMP_ULE:
      case CmpInst::ICMP_ULE:
        Signed = false;
        [[fallthrough]];
      case CmpInst::ICMP_SLE:
        Kind = BranchHint::LE;
        break;
      case CmpInst::FCMP_ONE:
      case CmpInst::FCMP_UNE:
      case CmpInst::ICMP_NE:
        Kind = BranchHint::NE;
        break;
      default:
        Kind = BranchHint::Invalid;
        break;
      }

      if (DominatesCallback(Other)) {
        for (auto *CmpUser : Cmp->users()) {
          if (auto *BI = dyn_cast<BranchInst>(CmpUser)) {
            BranchHint BHTrue = {Kind, Signed, Other,
                                 GetBlockProfileCount(*BI, 0), -1};
            BranchHint BHFalse = {GetNegated(Kind), Signed, Other,
                                  GetBlockProfileCount(*BI, 1), -1};
            BranchHints.push_back({BHTrue, BI->getSuccessor(0)});
            BranchHints.push_back({BHFalse, BI->getSuccessor(1)});
          }
        }
      }
    }
  }
}

std::array<Value *, 2> InputGenInstrumenter::getEmptyBranchHints() {
  IRBuilder<> IRB(M.getContext());
  return {Constant::getNullValue(IRB.getPtrTy()), IRB.getInt32(0)};
}

std::array<Value *, 2>
InputGenInstrumenter::getBranchHints(Value *V, IRBuilderBase &IRB,
                                     ValueToValueMapTy *VMap) {
  if (!ClProvideBranchHints || !V)
    return getEmptyBranchHints();

  assert(((!isa<Argument>(V) && !VMap) || (isa<Argument>(V) && VMap)) &&
         "Need to provide arg mapping only when getting branch hints for arg");

  Function *F;
  if (auto *Arg = dyn_cast<Argument>(V))
    F = Arg->getParent();
  else if (auto *I = dyn_cast<Instruction>(V))
    F = I->getFunction();
  else
    llvm_unreachable(
        "Branch hint called for value other than instruction or argument");

  FunctionAnalysisManager &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  const DominatorTree &DT = FAM.getResult<DominatorTreeAnalysis>(*F);
  const BlockFrequencyInfo &BFI = FAM.getResult<BlockFrequencyAnalysis>(*F);

  std::function<bool(Value *)> DominatesCallback;
  if (auto *Arg = dyn_cast<Argument>(V))
    DominatesCallback = [Arg](Value *Other) -> bool {
      // Arguments that appear earlier dominate (as we have already generated
      // them
      if (auto *OtherArg = dyn_cast<Argument>(Other))
        return OtherArg->getArgNo() < Arg->getArgNo();
      // Otherwise only constants and globals can dominate an argument
      return isa<Constant>(Other) || isa<GlobalValue>(Other);
    };
  else if (auto *I = dyn_cast<Instruction>(V))
    DominatesCallback = [&DT, I](Value *Other) -> bool {
      return DT.dominates(Other, I->getIterator());
    };
  else
    llvm_unreachable(
        "Branch hint called for value other than instruction or argument");

  SmallVector<BranchHintInfo> BranchHints;

  findAllBranchValues(V, BranchHints, DominatesCallback, BFI);
  std::sort(BranchHints.begin(), BranchHints.end(),
            [](BranchHintInfo &A, BranchHintInfo &B) {
              return A.BH.Frequency < B.BH.Frequency;
            });

  for (unsigned I = 0; I < BranchHints.size(); I++) {
    for (unsigned J = 0; J < BranchHints.size(); J++) {
      if (DT.properlyDominates(BranchHints[I].BB, BranchHints[J].BB) &&
          (BranchHints[J].BH.Dominator == -1 ||
           DT.properlyDominates(BranchHints[BranchHints[J].BH.Dominator].BB,
                                BranchHints[I].BB)))
        BranchHints[J].BH.Dominator = I;
    }
  }

  IRBuilder<> IRBEntry(F->getContext());
  IRBEntry.SetInsertPointPastAllocas(IRB.GetInsertPoint()->getFunction());

  Value *Length = IRB.getInt32(BranchHints.size());
  Value *Array;
  if (BranchHints.size() == 0) {
    Array = Constant::getNullValue(IRB.getPtrTy());
  } else {
    auto *StructTy = StructType::get(
        F->getContext(), {IRB.getInt32Ty(), IRB.getInt8Ty(), IRB.getPtrTy(),
                          IRB.getInt64Ty(), IRB.getInt32Ty()});
    Array = IRBEntry.CreateAlloca(StructTy, Length);
    for (unsigned I = 0; I < BranchHints.size(); I++) {
      const auto &BH = BranchHints[I].BH;
      Value *Struct = UndefValue::get(StructTy);
      auto *ValAlloca = IRBEntry.CreateAlloca(BH.Val->getType());
      Value *ToStore = BH.Val;
      if (VMap && isa<Argument>(ToStore)) {
        ToStore = (*VMap)[ToStore];
        assert(ToStore);
      }
      IRB.CreateStore(ToStore, ValAlloca);
      int Idx = 0;
      Struct = IRB.CreateInsertValue(Struct, IRB.getInt32(BH.Kind), Idx++);
      Struct = IRB.CreateInsertValue(Struct, IRB.getInt8(BH.Signed), Idx++);
      Struct = IRB.CreateInsertValue(Struct, ValAlloca, Idx++);
      Struct = IRB.CreateInsertValue(Struct, IRB.getInt64(BH.Frequency), Idx++);
      Struct = IRB.CreateInsertValue(Struct, IRB.getInt32(BH.Dominator), Idx++);
      IRB.CreateStore(Struct, IRB.CreateConstGEP1_64(StructTy, Array, I));
    }
  }
  return {Array, Length};
}

void InputGenInstrumenter::recordValueUsingCallbacks(Module &M,
                                                     IRBuilderBase &IRB,
                                                     CallbackCollectionTy &CC,
                                                     Value *V) {
  Type *T = V->getType();
  if (auto *ST = dyn_cast<StructType>(T)) {
    for (unsigned It = 0; It < ST->getNumElements(); It++) {
      V, recordValueUsingCallbacks(M, IRB, CC, IRB.CreateExtractValue(V, {It}));
    }
  } else if (auto *AT = dyn_cast<ArrayType>(T)) {
    auto Count = AT->getArrayNumElements();
    for (unsigned It = 0; It < Count; It++) {
      V, recordValueUsingCallbacks(M, IRB, CC, IRB.CreateExtractValue(V, {It}));
    }
  } else if (auto *VT = dyn_cast<VectorType>(T)) {
    if (!VT->getElementCount().isScalable()) {
      auto Count = VT->getElementCount().getFixedValue();
      for (unsigned It = 0; It < Count; It++)
        recordValueUsingCallbacks(
            M, IRB, CC, IRB.CreateExtractElement(V, IRB.getInt64(It)));
    } else {
      llvm_unreachable("Scalable vectors unsupported.");
    }
  } else {
    auto *OrigTy = T;
    if (isa<PointerType>(T) && T->getPointerAddressSpace())
      T = T->getPointerTo();
    FunctionCallee Fn = CC[T];
    if (!Fn.getCallee()) {
      LLVM_DEBUG(dbgs() << "No value record callback for " << *T << "\n");
      IRB.CreateIntrinsic(VoidTy, Intrinsic::trap, {});
    } else {
      SmallVector<Value *, 3> Args{getValueForInterface(IRB, V)};
      auto BHs = getBranchHints(nullptr, IRB, nullptr);
      Args.insert(Args.end(), BHs.begin(), BHs.end());
      IRB.CreateCall(Fn, Args);
    }
  }
}

Value *InputGenInstrumenter::constructTypeUsingCallbacks(
    Module &M, IRBuilderBase &IRB, CallbackCollectionTy &CC, Type *T,
    Value *ValueToReplace, ValueToValueMapTy *VMap) {
  if (auto *ST = dyn_cast<StructType>(T)) {
    Value *V = UndefValue::get(ST);
    for (unsigned It = 0; It < ST->getNumElements(); It++) {
      Type *ElTy = ST->getElementType(It);
      V = IRB.CreateInsertValue(
          V, constructTypeUsingCallbacks(M, IRB, CC, ElTy, nullptr, VMap),
          {It});
    }
    return V;
  } else if (auto *AT = dyn_cast<ArrayType>(T)) {
    Type *ElTy = AT->getElementType();
    auto Count = AT->getArrayNumElements();
    Value *V = UndefValue::get(AT);
    for (unsigned It = 0; It < Count; It++) {
      V = IRB.CreateInsertValue(
          V, constructTypeUsingCallbacks(M, IRB, CC, ElTy, nullptr, VMap),
          {It});
    }
    return V;
  } else if (auto *VT = dyn_cast<VectorType>(T)) {
    Type *ElTy = VT->getElementType();
    if (!VT->getElementCount().isScalable()) {
      auto Count = VT->getElementCount().getFixedValue();
      Value *V = UndefValue::get(VT);
      for (unsigned It = 0; It < Count; It++) {
        V = IRB.CreateInsertElement(
            V, constructTypeUsingCallbacks(M, IRB, CC, ElTy, nullptr, VMap),
            IRB.getInt64(It));
      }
      return V;
    } else {
      llvm_unreachable("Scalable vectors unsupported.");
    }
  } else {
    auto *OrigTy = T;
    if (isa<PointerType>(T) && T->getPointerAddressSpace())
      T = T->getPointerTo();
    FunctionCallee Fn = CC[T];
    if (!Fn.getCallee()) {
      LLVM_DEBUG(dbgs() << "No value gen callback for " << *T << "\n");
      IRB.CreateIntrinsic(VoidTy, Intrinsic::trap, {});
      return UndefValue::get(T);
    } else {
      return IRB.CreateAddrSpaceCast(
          IRB.CreateCall(Fn, getBranchHints(ValueToReplace, IRB, VMap)),
          OrigTy);
    }
  }
}

Value *InputGenInstrumenter::constructFpFromPotentialCallees(
    const CallBase &Caller, Value &V, IRBuilderBase &IRB,
    SetVector<Instruction *> &ToDelete) {
  LLVM_DEBUG(dbgs() << "get suitable FP " << V << " for "
                    << IRB.GetInsertBlock()->getParent()->getName() << '\n');
  auto &M = *IRB.GetInsertBlock()->getModule();
  SetVector<Constant *> CalleeSet;

  if (auto *CalleesMD = Caller.getMetadata(LLVMContext::MD_callees)) {
    for (auto &CalleeMD : CalleesMD->operands()) {
      auto *CalleeAsVMD = cast<ValueAsMetadata>(CalleeMD)->getValue();
      auto *Callee = cast<Function>(CalleeAsVMD);

      CalleeSet.insert(Callee);
    }
  }

  auto Callees = CalleeSet.takeVector();
  sort(Callees, [](const Constant *LHS, const Constant *RHS) {
    return LHS->getName() < RHS->getName();
  });

  auto *ArrTy =
      ArrayType::get(PointerType::getUnqual(V.getContext()), Callees.size());
  auto *CalleeArr = ConstantArray::get(ArrTy, Callees);

  auto *CalleeGV = [&]() {
    auto IsEquivalentGV = [&](GlobalVariable &GV) {
      return GV.isConstant() &&
             GV.getName().starts_with("__inputgen_fp_map_") &&
             GV.getInitializer() == CalleeArr;
    };
    if (auto It = find_if(M.globals(), IsEquivalentGV); It != M.global_end()) {
      return &*It;
    }
    auto *CalleeGV = new GlobalVariable(
        ArrTy, true, GlobalValue::WeakAnyLinkage, CalleeArr,
        "__inputgen_fp_map_" + std::to_string(FpMapNameCounter++));
    M.insertGlobalVariable(CalleeGV);
    return CalleeGV;
  }();

  auto *FPTy = PointerType::getUnqual(V.getContext());

  if (auto *LI = dyn_cast<LoadInst>(&V)) {
    if (LI->getFunction()->getName().starts_with(getCallbackPrefix(Mode) +
                                                 "entry_")) {
      // Loads in the entries are generated by us, remove again & use select
      // instead.
      if (auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand()))
        LI->replaceUsesOfWith(GEP, UndefValue::get(GEP->getType()));
    } else {
      if (Mode == IG_Generate) {
        if (auto *MemAccessI = LI->getPrevNonDebugInstruction())
          if (auto *MemAccessCal = dyn_cast<CallBase>(MemAccessI);
              MemAccessCal && MemAccessCal->getCalledFunction() &&
              MemAccessCal->getCalledFunction()->getName().starts_with(
                  "__inputgen_access"))
            ToDelete.insert(MemAccessCal);

        // void __inputgen_access_fp(VoidPtrTy Ptr, int32_t Size,
        //  VoidPtrTy Base, VoidPtrTy *PotentialFPs,
        //  uint64_t N)
        auto AccessFp = M.getOrInsertFunction(
            "__inputgen_access_fp",
            FunctionType::get(IRB.getVoidTy(),
                              {IRB.getPtrTy(), IRB.getInt32Ty(), IRB.getPtrTy(),
                               CalleeGV->getType(), IRB.getInt64Ty()},
                              false));
        IRB.CreateCall(AccessFp,
                       {LI->getPointerOperand(),
                        IRB.getInt32(M.getDataLayout().getPointerSize()),
                        LI->getPointerOperand(), CalleeGV,
                        IRB.getInt64(Callees.size())});
      }
      return nullptr;
    }
  }

  auto SelectFp = M.getOrInsertFunction(
      "__inputgen_select_fp",
      FunctionType::get(FPTy, {CalleeGV->getType(), IRB.getInt64Ty()}, false));

  return IRB.CreateCall(SelectFp, {CalleeGV, IRB.getInt64(Callees.size())});
}

namespace {
void gatherCallbackArguments(Function &F, SetVector<uint64_t> &FPArgs) {
  if (auto *CallbackMD = F.getMetadata(LLVMContext::MD_callback)) {
    for (auto &CBArgMD : CallbackMD->operands()) {
      if (auto *CBArgNode = dyn_cast<MDNode>(CBArgMD)) {
        auto *CBArgIdxMD = cast<ConstantAsMetadata>(CBArgNode->getOperand(0));
        auto CBArgIdx =
            cast<ConstantInt>(CBArgIdxMD->getValue())->getZExtValue();
        FPArgs.insert(CBArgIdx);
      }
    }
  }
}

AllocaInst *createSwiftErrorAlloca(IRBuilderBase &IRB) {
  auto *Alloca = IRB.CreateAlloca(IRB.getPtrTy());
  Alloca->setSwiftError(true);
  return Alloca;
}
} // namespace

void InputGenInstrumenter::createGenerationEntryPoint(Function &F,
                                                      bool UniqName) {
  Module &M = *F.getParent();
  F.setLinkage(GlobalValue::InternalLinkage);

  std::string EntryPointName = getCallbackPrefix(Mode) + "entry";
  if (UniqName) {
    EntryPointName += "_";
    EntryPointName += F.getName();
  }
  FunctionType *MainTy = FunctionType::get(Int32Ty, {Int32Ty, PtrTy}, false);
  auto *EntryPoint =
      Function::Create(MainTy, GlobalValue::ExternalLinkage, EntryPointName, M);
  EntryPoint->addFnAttr(Attribute::NoRecurse);

  auto *EntryBB = BasicBlock::Create(*Ctx, "entry", EntryPoint);

  auto *RI =
      ReturnInst::Create(*Ctx, ConstantInt::getNullValue(Int32Ty), EntryBB);
  IRBuilder<> IRB(RI);
  if (!F.isDeclaration())
    IRB.SetCurrentDebugLocation(
        F.getEntryBlock().getTerminator()->getDebugLoc());

  Function *InitF = M.getFunction("__input_gen_init");
  IRB.CreateCall(FunctionCallee(InitF->getFunctionType(), InitF), {});

  if (F.getFnAttribute("min-legal-vector-width").isValid())
    EntryPoint->addFnAttr(F.getFnAttribute("min-legal-vector-width"));

  SmallVector<Value *> Args;
  ValueToValueMapTy VMap;
  for (auto &Arg : F.args()) {
    if (Arg.hasSwiftErrorAttr())
      Args.push_back(createSwiftErrorAlloca(IRB));
    else
      Args.push_back(constructTypeUsingCallbacks(M, IRB, ArgGenCallback,
                                                 Arg.getType(), &Arg, &VMap));
    VMap[&Arg] = Args.back();
  }
  auto *Ret = IRB.CreateCall(FunctionCallee(F.getFunctionType(), &F), Args, "");

  // Do not inline the function. We can safely remove the always inline because
  // optimization passes up to this point will have used that attribute already.
  Ret->setIsNoInline();
  F.removeFnAttr(Attribute::AlwaysInline);

  SmallVector<ABIAttrs> FnABIInfo;
  collectABIInfo(F, FnABIInfo);
  Ret->setCallingConv(F.getCallingConv());
  IRBuilder<> IRB2(Ret);
  setABIInfo(*Ret, FnABIInfo, IRB2);

  if (Ret->getType()->isVoidTy())
    return;
  auto *Alloca = IRB.CreateAlloca(Ret->getType());
  IRB.CreateStore(Ret, Alloca);
  IRB.CreateCall(
      UseCallback,
      {Alloca, IRB.getInt32(F.getParent()->getDataLayout().getTypeAllocSize(
                   Ret->getType()))});
}

void InputGenInstrumenter::createRunEntryPoint(Function &F, bool UniqName) {
  Module &M = *F.getParent();
  F.setLinkage(GlobalValue::InternalLinkage);

  std::string EntryPointName = getCallbackPrefix(Mode) + "entry";
  if (UniqName) {
    EntryPointName += "_";
    EntryPointName += F.getName();
  }
  FunctionType *MainTy = FunctionType::get(VoidTy, {PtrTy}, false);
  auto *EntryPoint =
      Function::Create(MainTy, GlobalValue::ExternalLinkage, EntryPointName, M);
  EntryPoint->addFnAttr(Attribute::NoRecurse);

  auto *EntryBB = BasicBlock::Create(*Ctx, "entry", EntryPoint);

  auto *RI = ReturnInst::Create(*Ctx, EntryBB);
  IRBuilder<> IRB(RI);
  if (!F.isDeclaration())
    IRB.SetCurrentDebugLocation(
        F.getEntryBlock().getTerminator()->getDebugLoc());

  Function *InitF = M.getFunction("__input_gen_init");
  IRB.CreateCall(FunctionCallee(InitF->getFunctionType(), InitF), {});

  if (F.getFnAttribute("min-legal-vector-width").isValid())
    EntryPoint->addFnAttr(F.getFnAttribute("min-legal-vector-width"));

  Argument *ArgsPtr = EntryPoint->getArg(0);
  unsigned Idx = 0;
  auto GetNext = [&]() {
    Value *GEP = IRB.CreateGEP(PtrTy, ArgsPtr, {IRB.getInt64(Idx)});
    Idx += 2;
    return GEP;
  };
  SmallVector<Value *> Args;
  std::function<Value *(Type *, Value *)> HandleType;
  HandleType = [&](Type *T, Value *ValueToReplace) -> Value * {
    if (auto *ST = dyn_cast<StructType>(T)) {
      Value *V = UndefValue::get(ST);
      for (unsigned It = 0; It < ST->getNumElements(); It++) {
        Type *ElTy = ST->getElementType(It);
        V = IRB.CreateInsertValue(V, HandleType(ElTy, nullptr), {It});
      }
      return V;
    } else if (auto *AT = dyn_cast<ArrayType>(T)) {
      Type *ElTy = AT->getArrayElementType();
      Value *V = UndefValue::get(AT);
      auto Count = AT->getNumElements();
      for (unsigned It = 0; It < Count; It++) {
        V = IRB.CreateInsertValue(V, HandleType(ElTy, nullptr), {It});
      }
      return V;
    } else if (auto *VT = dyn_cast<VectorType>(T)) {
      Type *ElTy = VT->getElementType();
      if (!VT->getElementCount().isScalable()) {
        auto Count = VT->getElementCount().getFixedValue();
        Value *V = UndefValue::get(VT);
        for (unsigned It = 0; It < Count; It++) {
          V = IRB.CreateInsertElement(V, HandleType(ElTy, nullptr),
                                      IRB.getInt64(It));
        }
        return V;
        Args.push_back(V);
      } else {
        llvm_unreachable("Scalable vectors unsupported.");
      }
    } else {
      Value *ArgPtr = GetNext();
      Type *ElTy = T;
      return IRB.CreateLoad(ElTy, ArgPtr);
    }
  };

  SetVector<uint64_t> FPArgs;
  if (ClInstrumentFunctionPtrs)
    gatherCallbackArguments(F, FPArgs);
  SetVector<Instruction *> ToDelete;
  auto GetFPArg = [&](auto &Arg) {
    for (auto *U : Arg.users()) {
      if (auto *CI = dyn_cast<CallBase>(U);
          CI && CI->getCalledOperand() == &Arg) {
        return constructFpFromPotentialCallees(*CI, Arg, IRB, ToDelete);
      }
    }
    llvm_unreachable("Arg must be used when used as callback.");
  };

  for (uint64_t A = 0; A < F.arg_size(); ++A) {
    auto &Arg = *F.getArg(A);
    if (Arg.hasSwiftErrorAttr())
      Args.push_back(createSwiftErrorAlloca(IRB));
    else if (FPArgs.contains(A)) {
      assert(!Arg.users().empty() && "Arg must be used when used as FP.");
      Args.push_back(GetFPArg(Arg));
    } else {
      Args.push_back(HandleType(Arg.getType(), &Arg));
    }
  }

  for (auto *I : ToDelete)
    I->eraseFromParent();

  auto *Ret = IRB.CreateCall(FunctionCallee(F.getFunctionType(), &F), Args, "");

  // Do not inline the function. We can safely remove the always inline because
  // optimization passes up to this point will have used that attribute already.
  Ret->setIsNoInline();
  F.removeFnAttr(Attribute::AlwaysInline);

  SmallVector<ABIAttrs> FnABIInfo;
  collectABIInfo(F, FnABIInfo);
  Ret->setCallingConv(F.getCallingConv());
  IRBuilder<> IRB2(Ret);
  setABIInfo(*Ret, FnABIInfo, IRB2);

  if (Ret->getType()->isVoidTy())
    return;
  auto *Alloca = IRB.CreateAlloca(Ret->getType());
  IRB.CreateStore(Ret, Alloca);
  IRB.CreateCall(
      UseCallback,
      {Alloca, IRB.getInt32(F.getParent()->getDataLayout().getTypeAllocSize(
                   Ret->getType()))});
}

void InputGenInstrumenter::handleUnreachable(Module &M) {
  SmallVector<UnreachableInst *, 16> ToInstrumentUnreachable;
  for (auto &F : M)
    for (auto &I : instructions(F))
      if (auto *Unreachable = dyn_cast<UnreachableInst>(&I))
        ToInstrumentUnreachable.push_back(Unreachable);
  for (auto *Unreachable : ToInstrumentUnreachable)
    instrumentUnreachable(Unreachable);
}

void InputGenInstrumenter::instrumentFunction(Function &F) {
  LLVM_DEBUG(dbgs() << "INPUTGEN instrumenting:\n" << F.getName() << "\n");

  SmallVector<InterestingMemoryAccess, 16> ToInstrumentMem;
  SmallVector<ICmpInst *, 16> ToInstrumentCmp;
  SmallVector<UnreachableInst *, 16> ToInstrumentUnreachable;

  // Fill the set of memory operations to instrument.
  for (auto &I : instructions(F))
    if (auto IMA = isInterestingMemoryAccess(&I))
      ToInstrumentMem.push_back(*IMA);
    else if (auto *Cmp = dyn_cast<ICmpInst>(&I))
      ToInstrumentCmp.push_back(Cmp);
    else if (auto *Unreachable = dyn_cast<UnreachableInst>(&I))
      ToInstrumentUnreachable.push_back(Unreachable);
  if (ToInstrumentMem.empty() && ToInstrumentCmp.empty() &&
      ToInstrumentUnreachable.empty()) {
    LLVM_DEBUG(dbgs() << "INPUTGEN nothing to instrument in " << F.getName()
                      << "\n");
  }

  for (auto *Unreachable : ToInstrumentUnreachable)
    instrumentUnreachable(Unreachable);
  for (auto *Cmp : ToInstrumentCmp)
    instrumentCmp(Cmp);
  for (auto &IMA : ToInstrumentMem) {
    if (isa<MemIntrinsic>(IMA.I))
      instrumentMemIntrinsic(cast<MemIntrinsic>(IMA.I));
    else
      instrumentMop(IMA);
    NumInstrumented++;
  }

  LLVM_DEBUG(dbgs() << "INPUTGEN done instrumenting: " << ToInstrumentMem.size()
                    << " instructions in " << F.getName() << "\n");
}

namespace llvm {
void stripUnknownOperandBundles(Module &M) {
  SmallVector<unsigned, LLVMContext::OB_convergencectrl + 1> KnownOBs;
  for (unsigned OB = LLVMContext::OB_deopt;
       OB <= LLVMContext::OB_convergencectrl; OB++)
    KnownOBs.push_back(OB);
  SmallVector<CallBase *> ToRemove;
  for (auto &F : M.functions()) {
    for (auto &I : instructions(F)) {
      if (auto *CB = dyn_cast<CallBase>(&I)) {
        SmallVector<OperandBundleDef, 1> Bundles;
        for (unsigned I = 0, E = CB->getNumOperandBundles(); I != E; ++I) {
          auto Bundle = CB->getOperandBundleAt(I);
          if (is_contained(KnownOBs, Bundle.getTagID()))
            Bundles.emplace_back(Bundle);
        }
        auto *NewCall = CallBase::Create(CB, Bundles, CB);
        NewCall->copyMetadata(*CB);
        CB->replaceAllUsesWith(NewCall);
        ToRemove.push_back(CB);
      }
    }
  }
  for (auto *CB : ToRemove)
    CB->eraseFromParent();
}
} // namespace llvm
