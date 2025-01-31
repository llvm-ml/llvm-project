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
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
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

void EI::instrumentFunction(Module &M, Function &F) {
  // TODO
}

void EI::instrumentAll(Module &M) {
  SmallVector<Function *> ToInstrument;
  for (Function &F : M)
    ToInstrument.push_back(&F);
  for (Function *F : ToInstrument)
    instrumentFunction(M, *F);
}

bool EI::instrumentMarkedEntries(Module &M) {
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
} // namespace llvm
