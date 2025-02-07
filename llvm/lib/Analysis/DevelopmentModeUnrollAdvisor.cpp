//===-- UnrollLoopDevelopmentAdvisor.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/InteractiveModelRunner.h"
#include "llvm/Analysis/LoopPropertiesAnalysis.h"
#include "llvm/Analysis/MLModelRunner.h"
#include "llvm/Analysis/NoInferenceModelRunner.h"
#include "llvm/Analysis/ReleaseModeModelRunner.h"
#include "llvm/Analysis/TensorSpec.h"
#include "llvm/Analysis/UnrollAdvisor.h"
#include "llvm/Analysis/UnrollModelFeatureMaps.h"
#include "llvm/Analysis/Utils/TrainingLogger.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/LoopSimplify.h"
#include "llvm/Transforms/Utils/LoopUtils.h"
#include "llvm/Transforms/Utils/SimplifyIndVar.h"
#include "llvm/Transforms/Utils/UnrollLoop.h"
#include <algorithm>
#include <memory>

#define DEBUG_TYPE "loop-unroll-development-advisor"

using namespace llvm;

static cl::opt<std::string> InteractiveChannelBaseName(
    "loop-unroll-interactive-channel-base", cl::Hidden,
    cl::desc(
        "Base file path for the interactive mode. The incoming filename should "
        "have the name <inliner-interactive-channel-base>.in, while the "
        "outgoing name should be <inliner-interactive-channel-base>.out"));

using namespace llvm::mlgo;

namespace {
class DevelopmentUnrollAdvisor : public UnrollAdvisor {
public:
  DevelopmentUnrollAdvisor() {}
  ~DevelopmentUnrollAdvisor() {}

protected:
  std::unique_ptr<UnrollAdvice> getAdviceImpl(UnrollAdviceInfo UAI) override {
    if (!ModelRunner)
      // TODO Not sure if this is safe as if the LLVMContext that we pass in
      // here _could_ change from call to call to this function. It seems to
      // currently only be used to emit errors so it should be fine.
      ModelRunner = std::make_unique<InteractiveModelRunner>(
          UAI.L.getHeader()->getContext(), mlgo::UnrollFeatureMap,
          mlgo::UnrollDecisionSpec, InteractiveChannelBaseName + ".out",
          InteractiveChannelBaseName + ".in");

    LoopPropertiesInfo LPI =
        LoopPropertiesInfo::getLoopPropertiesInfo(&UAI.L, &UAI.LI, &UAI.SE);

#define SET(id, type, val)                                                     \
  *ModelRunner->getTensor<type>(UnrollFeatureIndex::id) = static_cast<type>(val);
    SET(loop_size, int64_t, UAI.UCE.getRolledLoopSize());
    SET(trip_count, int64_t, UAI.TripCount);
    SET(is_innermost_loop, int64_t, LPI.IsInnerMostLoop);
    SET(preheader_blocksize, int64_t, LPI.PreheaderBlocksize);
    SET(bb_count, int64_t, LPI.BasicBlockCount);
    SET(num_of_loop_latch, int64_t, LPI.LoopLatchCount);
    SET(load_inst_count, int64_t, LPI.LoadInstCount);
    SET(store_inst_count, int64_t, LPI.StoreInstCount);
    SET(logical_inst_count, int64_t, LPI.LogicalInstCount);
    SET(cast_inst_count, int64_t, LPI.CastInstCount);
#undef SET
    UnrollDecisionTy UD = ModelRunner->evaluate<UnrollDecisionTy>();
    auto MaxEl = std::max_element(UD.Out, UD.Out + MaxUnrollFactor);
    unsigned ArgMax = std::distance(UD.Out, MaxEl);

    return std::make_unique<UnrollAdvice>(this, ArgMax);
  }

private:
  std::unique_ptr<MLModelRunner> ModelRunner;
};
} // namespace

std::unique_ptr<UnrollAdvisor> llvm::getDevelopmentModeUnrollAdvisor() {
  return std::make_unique<DevelopmentUnrollAdvisor>();
}

// clang-format off
const std::vector<TensorSpec> llvm::mlgo::UnrollFeatureMap{
#define POPULATE_NAMES(DTYPE, SHAPE, NAME, __) \
  TensorSpec::createSpec<DTYPE>(#NAME, SHAPE),
  LOOP_UNROLL_FEATURE_ITERATOR(POPULATE_NAMES)
#undef POPULATE_NAMES
};
// clang-format on

const char *const llvm::mlgo::UnrollDecisionName = "unrolling_decision";
const TensorSpec llvm::mlgo::UnrollDecisionSpec =
    TensorSpec::createSpec<float>(UnrollDecisionName, {MaxUnrollFactor});

