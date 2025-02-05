//===-- UnrollLoopDevelopmentAdvisor.cpp ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "llvm/Analysis/LoopPropertiesAnalysis.h"
#include "llvm/Analysis/MLModelRunner.h"
#include "llvm/Analysis/NoInferenceModelRunner.h"
#include "llvm/Analysis/ReleaseModeModelRunner.h"
#include "llvm/Analysis/TensorSpec.h"
#include "llvm/Analysis/UnrollAdvisor.h"
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
#include <memory>

#define DEBUG_TYPE "loop-unroll-development-advisor"

using namespace llvm;

static cl::opt<std::string>
    TrainingLog("mlgo-unroll-training-log", cl::Hidden,
                cl::desc("Training log for loop partial unroll"));

namespace mlgo_loop_unroll {

/// These features are extracted by LoopPropertiesAnalysis
/// Tuple of (data_type, variable_name, shape, description)
#define LOOP_UNROLL_FEATURES_LIST(M)                                           \
  M(int64_t, loop_size, {1}, "size of loop")                                   \
  M(int64_t, trip_count, {1}, "static trip count of loop")                     \
  M(int64_t, is_innermost_loop, {1}, "whether the loop is the innermost loop") \
  M(int64_t, preheader_blocksize, {1}, "preheader blocksize (by instruction)") \
  M(int64_t, bb_count, {1}, "number of basic blocks (ignoring subloops)")      \
  M(int64_t, num_of_loop_latch, {1}, "number of loop latches")                 \
  M(int64_t, load_inst_count, {1}, "load instruction count")                   \
  M(int64_t, store_inst_count, {1}, "store instruction count")                 \
  M(int64_t, logical_inst_count, {1}, "logical instruction count")             \
  M(int64_t, cast_inst_count, {1}, "cast instruction count")

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

  LoopPropertiesInfo LPI =
      LoopPropertiesInfo::getLoopPropertiesInfo(&L, &LI, &SE);

#define SET(id, type, val)                                                     \
  *Runner->getTensor<type>(FeatureIDs::id) = static_cast<type>(val);
  SET(loop_size, int64_t, LoopSize);
  SET(trip_count, int64_t, TripCount);
  SET(is_innermost_loop, int64_t, LPI.IsInnerMostLoop);
  SET(preheader_blocksize, int64_t, LPI.PreheaderBlocksize);
  SET(bb_count, int64_t, LPI.BasicBlockCount);
  SET(num_of_loop_latch, int64_t, LPI.LoopLatchCount);
  SET(load_inst_count, int64_t, LPI.LoadInstCount);
  SET(store_inst_count, int64_t, LPI.StoreInstCount);
  SET(logical_inst_count, int64_t, LPI.LogicalInstCount);
  SET(cast_inst_count, int64_t, LPI.CastInstCount);
#undef SET
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

} // namespace mlgo_loop_unroll

namespace llvm {
class DevelopmentUnrollAdvisor : public UnrollAdvisor {
public:
  DevelopmentUnrollAdvisor() {}
  ~DevelopmentUnrollAdvisor() {}

protected:
  std::unique_ptr<UnrollAdvice> getAdviceImpl(UnrollAdviceInfo UAI) override {
    return std::make_unique<UnrollAdvice>(this, std::nullopt);
  }
};

std::unique_ptr<UnrollAdvisor> getDevelopmentModeUnrollAdvisor() {
  return std::make_unique<DevelopmentUnrollAdvisor>();
}

} // namespace llvm
