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

namespace mlgo_loop_unroll {

#if 0
// The model learns to decide whether or not to partial unroll a loop.
// If unroll_count == 0, a loop is not unrolled, otherwise it is unrolled by the
// factor of provided decision.
#define DecisionName "unroll_count"

enum FeatureIDs {
#define _FEATURE_IDX(_, name, __, ___) name,
  LOOP_UNROLL_FEATURES_LIST(_FEATURE_IDX)
#undef _FEATURE_IDX
      FeatureCount
};

#define DECL_FEATURES(type, name, shape, _)                                    \
  TensorSpec::createSpec<type>(#name, shape),

/// Input features for training. Note that in the future we can attempt to have
/// multiple sets of features for different purpose. For example a set of
/// input features in release mode.
static const std::vector<TensorSpec> InputFeatures{
    LOOP_UNROLL_FEATURES_LIST(DECL_FEATURES)};

/// A single output feature, the decision whether or not to loop partial unroll
static const TensorSpec OutputFeature =
    TensorSpec::createSpec<int32_t>("unroll_count", {1});

/// Currently a dummy reward at the moment. Required to be provided for
/// construction of logger.
static const TensorSpec RewardFeature =
    TensorSpec::createSpec<float>("reward", {1});

/// Class for MLGO in loop unroll. Since LoopUnrollPass is a LoopPass and we
/// will flush the logs after all features all collected, the compiler will
/// hold a local copy of this class. Logs will be dumped at the end of
/// compilation, which will be at the dtor of LoopUnrollPass.
struct MLGOLoopUnrollAnalysis {
public:
  /// Ctor for MLGO in loop unroll.
  MLGOLoopUnrollAnalysis(LLVMContext &Ctx) : Ctx(Ctx) {
    Runner = std::make_unique<NoInferenceModelRunner>(Ctx, InputFeatures);
  }

  MLGOLoopUnrollAnalysis() = delete;

  /// Set features for loop
  void setFeatures(const unsigned LoopSize, const unsigned TripCount,
                   LoopInfo &LI, ScalarEvolution &SE, Loop &L);

  /// Log features and partial unroll decision for loop
  void logFeaturesAndDecision(const unsigned PartialUnrollCount, Loop &L);

  /// Runner for MLModel (training(default) / training(model) / release)
  std::unique_ptr<MLModelRunner> Runner;

private:
  template <typename T> size_t getTotalSize(const std::vector<int64_t> &Shape) {
    size_t Ret = sizeof(T);
    for (const auto V : Shape)
      Ret *= V;
    return Ret;
  }

  void resetInputs() {
#define _RESET(type, name, shape, _)                                           \
  std::memset(Runner->getTensorUntyped(FeatureIDs::name), 0,                   \
              getTotalSize<type>(shape));
    LOOP_UNROLL_FEATURES_LIST(_RESET)
#undef _RESET
  }

  LLVMContext &Ctx;

  /// A logger for each loop. Key = "$(MODULE)###$(FUNCTION)###$(LOOP)"
  StringMap<std::unique_ptr<Logger>> LogMap;
};

void MLGOLoopUnrollAnalysis::setFeatures(const unsigned LoopSize,
                                         const unsigned TripCount, LoopInfo &LI,
                                         ScalarEvolution &SE, Loop &L) {
  resetInputs();
}

void MLGOLoopUnrollAnalysis::logFeaturesAndDecision(const unsigned UnrollCount,
                                                    Loop &L) {
  // Key = $(MODULE)###$(FUNCTION)###$(LOOP)
  std::string Key = L.getHeader()->getModule()->getName().str() + "###" +
                    L.getHeader()->getParent()->getName().str() + "###" +
                    L.getName().str();

  assert(!LogMap.count(Key) &&
         "Should only extract feature for every loop once");

  std::vector<TensorSpec> LFS;
  for (const auto &IF : InputFeatures)
    LFS.push_back(IF);
  LFS.push_back(OutputFeature);

  std::error_code EC;
  auto OS = std::make_unique<raw_fd_ostream>(TrainingLog, EC);
  if (EC) {
    Ctx.emitError(EC.message() + ":" + TrainingLog);
    return;
  }
  // Create Logger for loop and insert it to LogMap
  auto I = LogMap.insert((std::make_pair(
      Key, std::make_unique<Logger>(std::move(OS), LFS, RewardFeature,
                                    /* IncludeReward */ false))));
  assert(I.second && "Should be unique insertion");

  Logger *Log = I.first->second.get();
  Log->startObservation();
  size_t CurrentFeature = 0;
  for (; CurrentFeature < FeatureIDs::FeatureCount; ++CurrentFeature)
    Log->logTensorValue(CurrentFeature,
                        reinterpret_cast<const char *>(
                            Runner->getTensorUntyped(CurrentFeature)));

  Log->logTensorValue(CurrentFeature,
                      reinterpret_cast<const char *>(&UnrollCount));
  Log->endObservation();

  LLVM_DEBUG(
      dbgs() << "(MLGO) Logged features and loop partial unroll decision = "
             << UnrollCount << " for loop '" << Key << "'\n");
}

#endif

} // namespace mlgo_loop_unroll

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
    SET(loop_size, int64_t, UAI.LoopSize);
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

