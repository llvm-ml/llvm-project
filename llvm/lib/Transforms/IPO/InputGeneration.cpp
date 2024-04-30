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
#include "llvm/Transforms/IPO/InputGenerationImpl.h"

#include "llvm/ADT/EnumeratedArray.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/StringSwitch.h"
#include "llvm/ADT/iterator.h"
#include "llvm/Analysis/MemoryBuiltins.h"
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
#include "llvm/Transforms/IPO/InputGenerationImpl.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <cstdint>
#include <memory>

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

STATISTIC(NumInstrumented, "Number of instrumented instructions");

namespace {

bool isLibCGlobal(StringRef Name) {
  return StringSwitch<bool>(Name)
      .Case("stderr", true)
      .Case("stdout", true)
      .Default(false);
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

InputGenerationInstrumentPass::InputGenerationInstrumentPass() = default;

PreservedAnalyses
InputGenerationInstrumentPass::run(Module &M, AnalysisManager<Module> &MAM) {
  ModuleInputGenInstrumenter Profiler(M, MAM, ClInstrumentationMode);
  if (Profiler.instrumentClEntryPoint(M))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

// Instrument memset/memmove/memcpy
void InputGenInstrumenter::instrumentMemIntrinsic(MemIntrinsic *MI) {
  IRBuilder<> IRB(MI);
  IRB.SetCurrentDebugLocation(MI->getDebugLoc());
  if (isa<MemTransferInst>(MI)) {
    IRB.CreateCall(isa<MemMoveInst>(MI) ? InputGenMemmove : InputGenMemcpy,
                   {MI->getOperand(0), MI->getOperand(1), MI->getOperand(2)});
  } else if (isa<MemSetInst>(MI)) {
    IRB.CreateCall(InputGenMemset,
                   {MI->getOperand(0), MI->getOperand(1), MI->getOperand(2)});
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
    Access.Kind = InterestingMemoryAccess::READ;
    Access.AccessTy = LI->getType();
    Access.Addr = LI->getPointerOperand();
    Access.AddrOperandNo = 0;
  } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    Access.Kind = InterestingMemoryAccess::WRITE;
    Access.V = SI->getValueOperand();
    Access.AccessTy = SI->getValueOperand()->getType();
    Access.Addr = SI->getPointerOperand();
    Access.AddrOperandNo = 1;
  } else if (AtomicRMWInst *RMW = dyn_cast<AtomicRMWInst>(I)) {
    Access.Kind = InterestingMemoryAccess::READ_THEN_WRITE;
    Access.V = RMW->getValOperand();
    Access.AccessTy = RMW->getValOperand()->getType();
    Access.Addr = RMW->getPointerOperand();
    Access.AddrOperandNo = 0;
  } else if (AtomicCmpXchgInst *XCHG = dyn_cast<AtomicCmpXchgInst>(I)) {
    Access.Kind = InterestingMemoryAccess::READ_THEN_WRITE;
    Access.V = XCHG->getCompareOperand();
    Access.AccessTy = XCHG->getCompareOperand()->getType();
    Access.Addr = XCHG->getPointerOperand();
    Access.AddrOperandNo = 0;
  } else if (auto *CI = dyn_cast<CallInst>(I)) {
    auto *F = CI->getCalledFunction();
    if (F && (F->getIntrinsicID() == Intrinsic::masked_load ||
              F->getIntrinsicID() == Intrinsic::masked_store)) {
      unsigned OpOffset = 0;
      if (F->getIntrinsicID() == Intrinsic::masked_store) {
        // Masked store has an initial operand for the value.
        OpOffset = 1;
        Access.AccessTy = CI->getArgOperand(0)->getType();
        Access.Kind = InterestingMemoryAccess::WRITE;
      } else {
        Access.AccessTy = CI->getType();
        Access.Kind = InterestingMemoryAccess::READ;
      }

      auto *BasePtr = CI->getOperand(0 + OpOffset);
      Access.MaybeMask = CI->getOperand(2 + OpOffset);
      Access.Addr = BasePtr;
    }
    Access.AddrOperandNo = 0;
  }

  if (!Access.Addr)
    return std::nullopt;

  // Do not instrument accesses from different address spaces; we cannot deal
  // with them.
  Type *PtrTy = cast<PointerType>(Access.Addr->getType()->getScalarType());
  if (PtrTy->getPointerAddressSpace() != 0)
    return std::nullopt;

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

void InputGenInstrumenter::instrumentMaskedLoadOrStore(
    const InterestingMemoryAccess &Access, const DataLayout &DL) {
  llvm_unreachable("Not implemented yet");
}

void InputGenInstrumenter::instrumentMop(const InterestingMemoryAccess &Access,
                                         const DataLayout &DL) {

  if (Access.MaybeMask)
    instrumentMaskedLoadOrStore(Access, DL);
  else
    instrumentAddress(Access, DL);
}

void InputGenInstrumenter::instrumentAddress(
    const InterestingMemoryAccess &Access, const DataLayout &DL) {
  IRBuilder<> IRB(Access.I);
  IRB.SetCurrentDebugLocation(Access.I->getDebugLoc());
  SmallVector<const Value *, 4> Objects;
  getUnderlyingObjects(Access.Addr, Objects, /*LI=*/nullptr,
                       /*MaxLookup=*/12);

  Value *Object = Objects.size() == 1
                      ? const_cast<Value *>(Objects[0])
                      : getUnderlyingObject(Access.Addr, /*MaxLookup=*/12);

  if (isa<AllocaInst>(Object))
    return;
  if (isa<GlobalVariable>(Object))
    return;

  if (auto *ST = dyn_cast<StructType>(Access.AccessTy)) {
    for (unsigned It = 0; It < ST->getNumElements(); It++) {
      Type *ElTy = ST->getElementType(It);
      int32_t ElAllocSize = DL.getTypeAllocSize(ElTy);
      auto *GEP = IRB.CreateConstGEP2_32(Access.AccessTy, Access.Addr, 0, It);
      Value *V = nullptr;
      switch (Access.Kind) {
      case InterestingMemoryAccess::READ:
        assert(Access.V == nullptr);
        break;
      case InterestingMemoryAccess::WRITE:
        assert(Access.V != nullptr);
        V = IRB.CreateExtractValue(Access.V, {It});
        break;
      case InterestingMemoryAccess::READ_THEN_WRITE:
        break;
      }
      emitMemoryAccessCallback(IRB, GEP, V, ElTy, ElAllocSize, Access.Kind,
                               Object);
    }
  } else if (auto *VT = dyn_cast<VectorType>(Access.AccessTy)) {
    Type *ElTy = VT->getElementType();
    int32_t ElAllocSize = DL.getTypeAllocSize(ElTy);
    if (!VT->getElementCount().isScalable()) {
      auto Count = VT->getElementCount().getFixedValue();
      for (unsigned It = 0; It < Count; It++) {
        auto *GEP = IRB.CreateConstGEP2_64(Access.AccessTy, Access.Addr, 0, It);
        Value *V = nullptr;
        switch (Access.Kind) {
        case InterestingMemoryAccess::READ:
          assert(Access.V == nullptr);
          break;
        case InterestingMemoryAccess::WRITE:
          assert(Access.V != nullptr);
          V = IRB.CreateExtractElement(Access.V, IRB.getInt64(It));
          break;
        case InterestingMemoryAccess::READ_THEN_WRITE:
          break;
        }
        emitMemoryAccessCallback(IRB, GEP, V, ElTy, ElAllocSize, Access.Kind,
                                 Object);
      }
    } else {
      llvm_unreachable("Scalable vectors unsupported.");
    }
  } else {
    int32_t AllocSize = DL.getTypeAllocSize(Access.AccessTy);
    emitMemoryAccessCallback(IRB, Access.Addr, Access.V, Access.AccessTy,
                             AllocSize, Access.Kind, Object);
  }
  Access.I->setOperand(Access.AddrOperandNo,
                       emitTranslatePtrCall(IRB, Access.Addr));
}

Value *InputGenInstrumenter::emitTranslatePtrCall(IRBuilderBase &IRB,
                                                  Value *Addr) {

  auto Fn = InputGenTranslatePtr;
  assert(Fn.getCallee());
  return IRB.CreateCall(Fn, {Addr});
}

void InputGenInstrumenter::emitMemoryAccessCallback(
    IRBuilderBase &IRB, Value *Addr, Value *V, Type *AccessTy,
    int32_t AllocSize, InterestingMemoryAccess::KindTy Kind, Value *Object) {

  Value *Val;
  if (V) {
    // If the value cannot fit in an i64, we need to pass it by reference.
    if (AllocSize > 8) {
      AllocaInst *Alloca = IRB.CreateAlloca(AccessTy);
      BasicBlock &EntryBlock =
          IRB.GetInsertBlock()->getParent()->getEntryBlock();
      Alloca->moveBefore(EntryBlock, EntryBlock.getFirstNonPHIOrDbgOrAlloca());
      IRB.CreateStore(V, Alloca);
      Val = IRB.CreateBitOrPointerCast(Alloca, Int64Ty);
    } else if (AccessTy->isIntOrIntVectorTy()) {
      Val = IRB.CreateZExtOrTrunc(V, Int64Ty);
    } else {
      Val = IRB.CreateZExtOrTrunc(
          IRB.CreateBitOrPointerCast(
              V, IntegerType::get(IRB.getContext(), AllocSize * 8)),
          Int64Ty);
    }
  } else {
    Val = ConstantInt::getNullValue(Int64Ty);
  }

  Value *Args[] = {Addr, Val, ConstantInt::get(Int32Ty, AllocSize), Object,
                   ConstantInt::get(Int32Ty, Kind)};
  auto Fn = InputGenMemoryAccessCallback[AccessTy];
  if (!Fn.getCallee()) {
    LLVM_DEBUG(dbgs() << "No memory access callback for " << *AccessTy << "\n");
    llvm_unreachable("No memory access callback");
  }
  IRB.CreateCall(Fn, Args);
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

bool ModuleInputGenInstrumenter::instrumentModule(Module &M) {

  switch (IGI.Mode) {
  case IG_Run:
  case IG_Generate:
    if (auto *OldMain = M.getFunction("main"))
      OldMain->setName("__input_gen_user_main");
    break;
  case IG_Record:
    break;
  }

  IGI.initializeCallbacks(M);
  IGI.provideGlobals(M);

  switch (IGI.Mode) {
  case IG_Run:
    break;
  case IG_Generate:
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

std::unique_ptr<Module>
ModuleInputGenInstrumenter::generateEntryPointModule(Module &M,
                                                     Function &EntryPoint) {
  auto NewM = std::make_unique<Module>("entry_point_module", M.getContext());
  NewM->setTargetTriple(M.getTargetTriple());
  NewM->setDataLayout(M.getDataLayout());

  Function *EntryF = Function::Create(EntryPoint.getFunctionType(),
                                      GlobalValue::ExternalLinkage,
                                      EntryPoint.getName(), &*NewM);

  switch (IGI.Mode) {
  case IG_Record:
    IGI.createRecordingEntryPoint(*EntryF);
    break;
  case IG_Generate:
    IGI.createGenerationEntryPoint(*EntryF, true);
    break;
  case IG_Run:
    IGI.createRunEntryPoint(*EntryF, true);
    break;
  }

  return NewM;
}

bool ModuleInputGenInstrumenter::instrumentModuleForFunction(
    Module &M, Function &EntryPoint) {
  if (EntryPoint.isDeclaration()) {
    errs() << "Entry point is declaration, used \"" << EntryPoint.getName()
           << "\".\n";
    return false;
  }

  IGI.pruneModule(EntryPoint);
  instrumentModule(M);
  instrumentEntryPoint(M, EntryPoint, /*UniqName=*/false);

  return true;
}

void InputGenInstrumenter::initializeCallbacks(Module &M) {

  auto Prefix = getCallbackPrefix(Mode);

  Type *Types[] = {Int1Ty,   Int8Ty, Int16Ty, Int32Ty,  Int64Ty,
                   Int128Ty, PtrTy,  FloatTy, DoubleTy, X86_FP80Ty};
  for (Type *Ty : Types) {
    InputGenMemoryAccessCallback[Ty] =
        M.getOrInsertFunction(Prefix + "access_" + ::getTypeName(Ty), VoidTy,
                              PtrTy, Int64Ty, Int32Ty, PtrTy, Int32Ty);
    ValueGenCallback[Ty] =
        M.getOrInsertFunction(Prefix + "get_" + ::getTypeName(Ty), Ty);
  }

  InputGenMemmove =
      M.getOrInsertFunction(Prefix + "memmove", PtrTy, PtrTy, PtrTy, Int64Ty);
  InputGenMemcpy =
      M.getOrInsertFunction(Prefix + "memcpy", PtrTy, PtrTy, PtrTy, Int64Ty);
  InputGenMemset =
      M.getOrInsertFunction(Prefix + "memset", PtrTy, PtrTy, Int8Ty, Int64Ty);

  InputGenTranslatePtr =
      M.getOrInsertFunction(Prefix + "translate_ptr", PtrTy, PtrTy);
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

    LibFunc LF;
    if (TLI.getLibFunc(F, LF) && TLI.has(LF))
      continue;

    F.setLinkage(GlobalValue::WeakAnyLinkage);
    auto *EntryBB = BasicBlock::Create(*Ctx, "entry", &F);

    IRBuilder<> IRB(EntryBB);
    //  IRB.SetCurrentDebugLocation();

    auto *RTy = F.getReturnType();
    if (RTy->isVoidTy())
      IRB.CreateRetVoid();
    else if (ValueGenCallback.count(RTy))
      IRB.CreateRet(IRB.CreateCall(ValueGenCallback[RTy]));
    else
      IRB.CreateRet(Constant::getNullValue(RTy));
  }
}

void InputGenInstrumenter::provideGlobals(Module &M) {
  for (GlobalVariable &GV : M.globals()) {
    if (isLibCGlobal(GV.getName()))
      continue;
    if (GV.hasExternalLinkage() || !GV.isConstant())
      MaybeExtInitializedGlobals.push_back({&GV, nullptr});
    if (!GV.hasExternalLinkage())
      continue;
    GV.setConstant(false);
    GV.setLinkage(GlobalValue::CommonLinkage);
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
      if (!ReplVal)
        ReplVal = new LoadInst(
            GV.getType(), &GVPtr, GV.getName() + ".reload",
            UserI->getFunction()->getEntryBlock().getFirstInsertionPt());
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
      RecordingCallbackPrefix + "push", FunctionType::get(VoidTy, false));
  IRB.CreateCall(PushFn, {});

  for (auto &Arg : F.args()) {
    FunctionCallee ArgPtrFn = M.getOrInsertFunction(
        RecordingCallbackPrefix + "arg_" + ::getTypeName(Arg.getType()),
        FunctionType::get(Arg.getType(), {Arg.getType()}, false));
    IRB.CreateCall(ArgPtrFn, {&Arg});
  }

  FunctionCallee PopFn = M.getOrInsertFunction(
      RecordingCallbackPrefix + "pop", FunctionType::get(VoidTy, false));
  for (auto &I : instructions(F)) {
    if (!isa<ReturnInst>(I))
      continue;
    IRB.SetInsertPoint(&I);
    IRB.SetCurrentDebugLocation(I.getDebugLoc());
    IRB.CreateCall(PopFn, {});
  }
}

void InputGenInstrumenter::createGlobalCalls(Module &M, IRBuilder<> &IRB) {
  auto DL = M.getDataLayout();
  FunctionCallee GVFn = M.getOrInsertFunction(
      InputGenCallbackPrefix + "global",
      FunctionType::get(VoidTy, {Int32Ty, PtrTy, PtrTy, Int32Ty}, false));

  auto *NumGlobalsVal =
      ConstantInt::get(Int32Ty, MaybeExtInitializedGlobals.size());
  for (auto &It : MaybeExtInitializedGlobals) {
    auto *GV = It.first;
    auto *GVPtr = It.second ? It.second : Constant::getNullValue(PtrTy);
    auto GVSize = DL.getTypeAllocSize(GV->getValueType());
    IRB.CreateCall(
        GVFn, {NumGlobalsVal, GV, GVPtr, ConstantInt::get(Int32Ty, GVSize)});
  }
}

void InputGenInstrumenter::createGenerationEntryPoint(Function &F,
                                                      bool UniqName) {
  Module &M = *F.getParent();

  std::string EntryPointName = getCallbackPrefix(Mode) + "entry";
  if (UniqName) {
    EntryPointName += "_";
    EntryPointName += F.getName();
  }
  FunctionType *MainTy = FunctionType::get(Int32Ty, {Int32Ty, PtrTy}, false);
  auto *EntryPoint =
      Function::Create(MainTy, GlobalValue::ExternalLinkage, EntryPointName, M);
  auto *EntryBB = BasicBlock::Create(*Ctx, "entry", EntryPoint);

  auto *RI =
      ReturnInst::Create(*Ctx, ConstantInt::getNullValue(Int32Ty), EntryBB);
  IRBuilder<> IRB(RI);
  if (!F.isDeclaration())
    IRB.SetCurrentDebugLocation(
        F.getEntryBlock().getTerminator()->getDebugLoc());

  Function *InitF = M.getFunction("__input_gen_init");
  IRB.CreateCall(FunctionCallee(InitF->getFunctionType(), InitF), {});

  SmallVector<Value *> Args;
  for (auto &Arg : F.args()) {
    if (auto *ST = dyn_cast<StructType>(Arg.getType())) {
      Value *V = UndefValue::get(ST);
      for (unsigned It = 0; It < ST->getNumElements(); It++) {
        Type *ElTy = ST->getElementType(It);
        FunctionCallee ArgFn = M.getOrInsertFunction(
            InputGenCallbackPrefix + "arg_" + ::getTypeName(ElTy),
            FunctionType::get(ElTy, false));
        V = IRB.CreateInsertValue(V, IRB.CreateCall(ArgFn, {}), {It});
      }
      Args.push_back(V);
    } else if (auto *VT = dyn_cast<VectorType>(Arg.getType())) {
      Type *ElTy = VT->getElementType();
      if (!VT->getElementCount().isScalable()) {
        auto Count = VT->getElementCount().getFixedValue();
        Value *V = UndefValue::get(VT);
        FunctionCallee ArgFn = M.getOrInsertFunction(
            InputGenCallbackPrefix + "arg_" + ::getTypeName(ElTy),
            FunctionType::get(ElTy, false));
        for (unsigned It = 0; It < Count; It++) {
          V = IRB.CreateInsertElement(V, IRB.CreateCall(ArgFn, {}),
                                      IRB.getInt64(It));
        }
        Args.push_back(V);
      } else {
        llvm_unreachable("Scalable vectors unsupported.");
      }
    } else {
      FunctionCallee ArgFn = M.getOrInsertFunction(
          InputGenCallbackPrefix + "arg_" + ::getTypeName(Arg.getType()),
          FunctionType::get(Arg.getType(), false));
      Args.push_back(IRB.CreateCall(ArgFn, {}));
    }
  }
  IRB.CreateCall(FunctionCallee(F.getFunctionType(), &F), Args, "");
}

void InputGenInstrumenter::createRunEntryPoint(Function &F, bool UniqName) {
  Module &M = *F.getParent();

  std::string EntryPointName = getCallbackPrefix(Mode) + "entry";
  if (UniqName) {
    EntryPointName += "_";
    EntryPointName += F.getName();
  }
  FunctionType *MainTy = FunctionType::get(VoidTy, {PtrTy}, false);
  auto *EntryPoint =
      Function::Create(MainTy, GlobalValue::ExternalLinkage, EntryPointName, M);
  auto *EntryBB = BasicBlock::Create(*Ctx, "entry", EntryPoint);

  auto *RI = ReturnInst::Create(*Ctx, EntryBB);
  IRBuilder<> IRB(RI);
  if (!F.isDeclaration())
    IRB.SetCurrentDebugLocation(
        F.getEntryBlock().getTerminator()->getDebugLoc());

  Function *InitF = M.getFunction("__input_gen_init");
  IRB.CreateCall(FunctionCallee(InitF->getFunctionType(), InitF), {});

  Argument *ArgsPtr = EntryPoint->getArg(0);
  unsigned Idx = 0;
  SmallVector<Value *> Args;
  for (auto &Arg : F.args()) {
    Value *ArgPtr = IRB.CreateGEP(PtrTy, ArgsPtr, {IRB.getInt64(Idx++)});
    Value *Load = IRB.CreateLoad(Arg.getType(), ArgPtr);
    Args.push_back(Load);
  }
  IRB.CreateCall(FunctionCallee(F.getFunctionType(), &F), Args, "");
}

void InputGenInstrumenter::instrumentFunction(Function &F) {

  LLVM_DEBUG(dbgs() << "INPUTGEN instrumenting:\n" << F.getName() << "\n");

  SmallVector<InterestingMemoryAccess, 16> ToInstrument;

  // Fill the set of memory operations to instrument.
  for (auto &I : instructions(F))
    if (auto IMA = isInterestingMemoryAccess(&I))
      ToInstrument.push_back(*IMA);

  if (ToInstrument.empty()) {
    LLVM_DEBUG(dbgs() << "INPUTGEN nothing to instrument in " << F.getName()
                      << "\n");
  }

  auto DL = F.getParent()->getDataLayout();

  for (auto &IMA : ToInstrument) {
    if (isa<MemIntrinsic>(IMA.I))
      instrumentMemIntrinsic(cast<MemIntrinsic>(IMA.I));
    else
      instrumentMop(IMA, DL);
    NumInstrumented++;
  }

  LLVM_DEBUG(dbgs() << "INPUTGEN done instrumenting: " << ToInstrument.size()
                    << " instructions in " << F.getName() << "\n");
}
