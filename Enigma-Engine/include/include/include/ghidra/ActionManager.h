#pragma once

#include <ghidra/Action.h>
#include <ghidra/Rule.h>
#include <ghidra/Types.h>
#include <string>
#include <vector>
#include <map>

namespace ghidra {

class Funcdata;
class Architecture;

class ActionManager {
public:
    enum Pipeline {
        PIPELINE_PREPROCESS = 0,
        PIPELINE_CONSTANT,
        PIPELINE_COPYPROP,
        PIPELINE_DEADCODE,
        PIPELINE_MERGE,
        PIPELINE_TYPEPROP,
        PIPELINE_TRANSFORM,
        PIPELINE_POSTPROCESS,
        PIPELINE_MAX
    };

private:
    std::map<Pipeline, ActionList*> pipelines;
    RuleLibrary ruleLibrary;
    Architecture* architecture;
    int4 totalIterations;
    int4 maxTotalIterations;
    bool verbose;

public:
    ActionManager(Architecture* arch);
    ~ActionManager();

    void initialize();
    void execute(Funcdata& fd);
    void executePipeline(Pipeline p, Funcdata& fd);

    void setVerbose(bool val) { verbose = val; }
    bool isVerbose() const { return verbose; }
    int4 getTotalIterations() const { return totalIterations; }
    int4 getMaxTotalIterations() const { return maxTotalIterations; }
    void setMaxTotalIterations(int4 val) { maxTotalIterations = val; }

    RuleLibrary& getRuleLibrary() { return ruleLibrary; }
    const RuleLibrary& getRuleLibrary() const { return ruleLibrary; }

    ActionList* getPipeline(Pipeline p) const;
    void setPipeline(Pipeline p, ActionList* list);

    void enableAllRules();
    void disableAllRules();
    void enableRule(const std::string& name);
    void disableRule(const std::string& name);

    void resetCounts();
};

class ActionConstantFold : public Action {
public:
    ActionConstantFold();
    ~ActionConstantFold() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionCopyPropagate : public Action {
public:
    ActionCopyPropagate();
    ~ActionCopyPropagate() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionDeadCodeElim : public Action {
public:
    ActionDeadCodeElim();
    ~ActionDeadCodeElim() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionMergeVarnodes : public Action {
public:
    ActionMergeVarnodes();
    ~ActionMergeVarnodes() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionTypePropagate : public Action {
private:
    Architecture* architecture;
public:
    ActionTypePropagate(Architecture* arch = nullptr);
    ~ActionTypePropagate() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionLandmark : public Action {
public:
    ActionLandmark();
    ~ActionLandmark() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionUnreachable : public Action {
public:
    ActionUnreachable();
    ~ActionUnreachable() override = default;
    uint4 apply(Funcdata& fd) override;
};

class ActionSwitchRecovery : public Action {
public:
    ActionSwitchRecovery();
    ~ActionSwitchRecovery() override = default;
    uint4 apply(Funcdata& fd) override;
};

} // namespace ghidra
