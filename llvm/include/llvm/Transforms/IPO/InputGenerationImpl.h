//===-------- Definition of the input generation passes ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines the implementation for the input-gen instrumentation that
// can be used by tools as well.
//
// The EntryInstrumenter must be ran before the MemoryInstrumenter.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H

#include "llvm/IR/Function.h"

namespace llvm {

enum class IGIMode : unsigned { Record, Generate, Replay, Disabled };

/// Prepares the entry points into functions for generation, recording, or
/// replaying.
class InputGenEntryInstrumenter {
public:
  InputGenEntryInstrumenter(IGIMode Mode) : Mode(Mode) {}

  /// Instruments only a specific function.
  void instrumentFunction(Module &M, Function &F);

  /// Instruments functinos marked by the inputgen_entry attribute.
  bool instrumentMarkedEntries(Module &M);

  /// Instruments all functions.
  void instrumentAll(Module &M);

private:
  IGIMode Mode;
};

/// Instruments the memory effects of all functions with prepared by
/// InputGenEntryInstrumenter entries.
class InputGenMemoryInstrumenter {
public:
  InputGenMemoryInstrumenter(IGIMode Mode) : Mode(Mode) {}

  /// Instruments
  bool instrument(Module &M);

private:
  IGIMode Mode;
};

} // namespace llvm

#endif
