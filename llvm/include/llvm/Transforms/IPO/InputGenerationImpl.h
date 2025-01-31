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
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_INPUTGENERATIONIMPL_H


namespace llvm {

enum IGInstrumentationModeTy { IG_Record, IG_Generate, IG_Replay, IG_Disabled };

} // namespace llvm

#endif
