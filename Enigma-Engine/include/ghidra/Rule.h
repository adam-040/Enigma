#pragma once

#include <ghidra/Action.h>
#include <ghidra/Types.h>
#include <string>
#include <vector>

namespace ghidra {

class PcodeOpAST;
class VarnodeAST;
class Funcdata;

class Rule {
public:
    enum RuleType {
        RULE_NONE = 0,
        RULE_CONSTANT,
        RULE_COPY,
        RULE_DEADCODE,
        RULE_MERGE,
        RULE_TYPEPROP,
        RULE_TRANSFORM,
        RULE_MAX
    };

protected:
    std::string name;
    RuleType type;
    bool enabled;
    int4 applyCount;

public:
    Rule(const std::string& nm, RuleType t);
    virtual ~Rule() = default;

    virtual bool applyOp(PcodeOpAST* op, Funcdata& fd) = 0;

    const std::string& getName() const { return name; }
    RuleType getType() const { return type; }
    bool isEnabled() const { return enabled; }
    int4 getApplyCount() const { return applyCount; }

    void setEnabled(bool val) { enabled = val; }
    void resetCount() { applyCount = 0; }
};

class RuleConstant : public Rule {
public:
    RuleConstant();
    ~RuleConstant() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleCopyPropagate : public Rule {
public:
    RuleCopyPropagate();
    ~RuleCopyPropagate() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleDeadCode : public Rule {
public:
    RuleDeadCode();
    ~RuleDeadCode() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleMergeVarnodes : public Rule {
public:
    RuleMergeVarnodes();
    ~RuleMergeVarnodes() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleTypePropagation : public Rule {
public:
    RuleTypePropagation();
    ~RuleTypePropagation() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RulePushMulti : public Rule {
public:
    RulePushMulti();
    ~RulePushMulti() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RulePullMulti : public Rule {
public:
    RulePullMulti();
    ~RulePullMulti() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleSimplifyBoolean : public Rule {
public:
    RuleSimplifyBoolean();
    ~RuleSimplifyBoolean() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleUnusedOutput : public Rule {
public:
    RuleUnusedOutput();
    ~RuleUnusedOutput() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleZeroExtension : public Rule {
public:
    RuleZeroExtension();
    ~RuleZeroExtension() override = default;
    bool applyOp(PcodeOpAST* op, Funcdata& fd) override;
};

class RuleLibrary {
private:
    std::vector<Rule*> rules;
    std::vector<Rule*> activeRules;

public:
    RuleLibrary();
    ~RuleLibrary();

    void addRule(Rule* rule);
    void removeRule(Rule* rule);
    void clear();

    Rule* getRule(const std::string& name) const;
    Rule* getRule(int4 index) const;
    int4 getNumRules() const { return static_cast<int4>(rules.size()); }
    int4 getNumActiveRules() const { return static_cast<int4>(activeRules.size()); }

    void enableAll();
    void disableAll();
    void enableRule(const std::string& name);
    void disableRule(const std::string& name);

    void rebuildActiveList();
    const std::vector<Rule*>& getActiveRules() const { return activeRules; }

    uint4 applyAll(Funcdata& fd);
    uint4 applyAllWithContext(Funcdata& fd);
};

} // namespace ghidra
