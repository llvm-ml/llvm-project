//===-------- Definition of the input generation passes ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file declares the input generation pass that is used, together with a
// runtime, to generate inputs for code snippets.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_IPO_INPUTGENERATION_H
#define LLVM_TRANSFORMS_IPO_INPUTGENERATION_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Module;

class InputGenInstrumentEntriesPass
    : public PassInfoMixin<InputGenInstrumentEntriesPass> {
public:
  explicit InputGenInstrumentEntriesPass();
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};
class InputGenInstrumentMemoryPass
    : public PassInfoMixin<InputGenInstrumentMemoryPass> {
public:
  explicit InputGenInstrumentMemoryPass();
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif
