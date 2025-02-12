//===- InputGeneration.cpp - Input generation instrumentation -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of input-gen. The idea is that we generate inputs for a
// piece of code by instrumenting it and running it once (per input) with a
// dedicated runtime. Each run yields an input (arguments and memory state) for
// the original piece of code.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/InputGeneration.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/IPO/InputGenerationImpl.h"

using namespace llvm;

#define DEBUG_TYPE "inputgen"

static cl::opt<IGIMode> ClInstrumentationMode(
    "input-gen-mode", cl::desc("Instrumentation mode"), cl::Hidden,
    cl::init(IGIMode::Disabled),
    cl::values(clEnumValN(IGIMode::Disabled, "disable", ""),
               clEnumValN(IGIMode::Record, "record", ""),
               clEnumValN(IGIMode::Generate, "generate", ""),
               clEnumValN(IGIMode::Replay, "replay", "")));

namespace llvm {

using EI = InputGenEntryInstrumenter;
using MI = InputGenMemoryInstrumenter;

std::string EI::getPrefix() const {
  switch (Mode) {
  case IGIMode::Generate:
    return "__inputgen_generate_";
  case IGIMode::Replay:
    return "__inputgen_replay_";
  case IGIMode::Record:
  default:
    llvm_unreachable("");
  }
}

void EI::preprocessModule() {
  switch (Mode) {
  case IGIMode::Generate:
    removeTokenFunctions();

  case IGIMode::Replay:

  case IGIMode::Record:
  default:
    llvm_unreachable("");
  }
}

void EI::renameGlobals(Module &M, TargetLibraryInfo &TLI) {
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

bool EI::instrumentMarkedEntries(Module &M) {

  preprocessModule(M);

  SmallVector<Function *> ToInstrument;
  for (Function &F : M)
    if (F.hasFnAttribute(llvm::Attribute::InputGenEntry))
      ToInstrument.push_back(&F);
  if (ToInstrument.size() == 0)
    return false;
  for (Function *F : ToInstrument)
    instrumentFunction(M, *F);
  return true;
}

bool MI::instrument(Module &M) { return true; }

InputGenInstrumentEntriesPass::InputGenInstrumentEntriesPass() = default;

PreservedAnalyses
InputGenInstrumentEntriesPass::run(Module &M, AnalysisManager<Module> &MAM) {
  if (ClInstrumentationMode == IGIMode::Disabled)
    return PreservedAnalyses::all();
  InputGenEntryInstrumenter IGEI(ClInstrumentationMode);
  if (IGEI.instrumentMarkedEntries(M))
    // FIXME PreservedAnalyses
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

InputGenInstrumentMemoryPass::InputGenInstrumentMemoryPass() = default;

PreservedAnalyses
InputGenInstrumentMemoryPass::run(Module &M, AnalysisManager<Module> &MAM) {
  if (ClInstrumentationMode == IGIMode::Disabled)
    return PreservedAnalyses::all();
  InputGenMemoryInstrumenter IGMI(ClInstrumentationMode);
  if (IGMI.instrument(M))
    // FIXME PreservedAnalyses
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

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
        auto *NewCall = CallBase::Create(CB, Bundles, CB->getIterator());
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
