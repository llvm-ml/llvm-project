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
#include "llvm/Support/raw_ostream.h"
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
#define DBGS() llvm::dbgs() << "mlgo-loop-unroll: "

using namespace llvm;

static cl::opt<std::string> InteractiveChannelBaseName(
    "mlgo-loop-unroll-interactive-channel-base", cl::Hidden,
    cl::desc(
        "Base file path for the interactive mode. The incoming filename should "
        "have the name <name>.in, while the outgoing name should be "
        "<name>.out"));

static cl::opt<std::string> ActionFeedbackChannelName(
    "mlgo-loop-unroll-action-feedback-channel", cl::Hidden,
    cl::desc("File path for the feedback channel. The compiler will send the "
             "result of the use of the advice to this channel."));

using namespace llvm::mlgo;

namespace {

class DevelopmentUnrollAdvisor : public UnrollAdvisor {
public:
  DevelopmentUnrollAdvisor() {}
  ~DevelopmentUnrollAdvisor() {}

  void onAction() {
    if (ActionFeedbackOut)
      ActionFeedbackOut->write(1);
  }
  void onNoAction() {
    if (ActionFeedbackOut)
      ActionFeedbackOut->write(0);
  }

protected:
  std::unique_ptr<UnrollAdvice> getAdviceImpl(UnrollAdviceInfo UAI) override;

private:
  std::unique_ptr<MLModelRunner> ModelRunner;
  std::unique_ptr<raw_fd_ostream> ActionFeedbackOut;
  LLVMContext *Ctx;
};

class DevelopmentUnrollAdvice : public UnrollAdvice {
public:
  using UnrollAdvice::UnrollAdvice;
  void recordUnrollingImpl() override {
    LLVM_DEBUG(DBGS() << "unrolled\n");
    getAdvisor()->onAction();
  }
  void
  recordUnsuccessfulUnrollingImpl(const LoopUnrollResult &Result) override {
    LLVM_DEBUG(DBGS() << "unsuccessful unroll\n");
    getAdvisor()->onNoAction();
  }
  void recordUnattemptedUnrollingImpl() override {
    LLVM_DEBUG(DBGS() << "unattempted unroll\n");
    getAdvisor()->onNoAction();
  }

private:
  DevelopmentUnrollAdvisor *getAdvisor() const {
    return static_cast<DevelopmentUnrollAdvisor *>(Advisor);
  };
};

std::unique_ptr<UnrollAdvice>
DevelopmentUnrollAdvisor::getAdviceImpl(UnrollAdviceInfo UAI) {
  if (!ModelRunner) {
    Ctx = &UAI.L.getHeader()->getContext();
    // TODO Not sure if this is safe as if the LLVMContext that we pass in
    // here _could_ change from call to call to this function. It seems to
    // currently only be used to emit errors so it should be fine.
    ModelRunner = std::make_unique<InteractiveModelRunner>(
        *Ctx, mlgo::UnrollFeatureMap, mlgo::UnrollDecisionSpec,
        InteractiveChannelBaseName + ".out",
        InteractiveChannelBaseName + ".in");
    if (ActionFeedbackChannelName.getNumOccurrences() > 0) {
      std::error_code EC;
      ActionFeedbackOut =
          std::make_unique<raw_fd_ostream>(ActionFeedbackChannelName, EC);
      if (EC) {
        Ctx->emitError("Cannot open outbound file: " + EC.message());
        ActionFeedbackOut.reset();
      }
    }
  }

  LoopPropertiesInfo LPI =
      LoopPropertiesInfo::getLoopPropertiesInfo(&UAI.L, &UAI.LI, &UAI.SE);

#define SET(id, type, val)                                                     \
  *ModelRunner->getTensor<type>(UnrollFeatureIndex::id) =                      \
      static_cast<type>(val);
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

  // The model gives us a speedup estimate for each unroll factor in
  // [2,MaxUnrollFactor] whose indices are offset by UnrollFactorOffset.
  UnrollDecisionTy UD = ModelRunner->evaluate<UnrollDecisionTy>();
  auto MaxEl = std::max_element(UD.Out, UD.Out + UnrollModelOutputLength);

  // Only unroll if the biggest estimated speedup is greater than 1.0.
  std::optional<unsigned> UnrollFactor;
  if (*MaxEl > 1.0) {
    unsigned ArgMax = std::distance(UD.Out, MaxEl);
    UnrollFactor = ArgMax + UnrollFactorOffset;
    LLVM_DEBUG(DBGS() << "got advice factor " << *UnrollFactor << "\n");
  } else {
    UnrollFactor = std::nullopt;
    LLVM_DEBUG(DBGS() << "got advice nounroll\n");
  }

  return std::make_unique<DevelopmentUnrollAdvice>(this, UnrollFactor);
}

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
const TensorSpec llvm::mlgo::UnrollDecisionSpec = TensorSpec::createSpec<float>(
    UnrollDecisionName, {UnrollModelOutputLength});
