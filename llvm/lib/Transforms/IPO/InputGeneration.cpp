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
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/InputGenerationImpl.h"

using namespace llvm;

#define DEBUG_TYPE "inputgen"

static cl::opt<IGInstrumentationModeTy>
    ClInstrumentationMode("input-gen-mode", cl::desc("Instrumentation mode"),
                          cl::Hidden, cl::init(IG_Disabled),
                          cl::values(clEnumValN(IG_Disabled, "disable", ""),
                                     clEnumValN(IG_Record, "record", ""),
                                     clEnumValN(IG_Generate, "generate", ""),
                                     clEnumValN(IG_Replay, "replay", "")));

namespace llvm {

InputGenInstrumentEntriesPass::InputGenInstrumentEntriesPass() = default;

PreservedAnalyses
InputGenInstrumentEntriesPass::run(Module &M, AnalysisManager<Module> &MAM) {
  if (ClInstrumentationMode == IG_Disabled)
    return PreservedAnalyses::all();
  return PreservedAnalyses::all();
}

InputGenInstrumentMemoryPass::InputGenInstrumentMemoryPass() = default;

PreservedAnalyses
InputGenInstrumentMemoryPass::run(Module &M, AnalysisManager<Module> &MAM) {
  if (ClInstrumentationMode == IG_Disabled)
    return PreservedAnalyses::all();
  return PreservedAnalyses::all();
}
} // namespace llvm
