#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class ScalarOperandAnalyzer : public AbstractAnalyzer {
public:
    ScalarOperandAnalyzer();
    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

protected:
    ScalarOperandAnalyzer(const std::string& name, const std::string& description);

    void checkOperands(Program* program, Instruction* instr);
    virtual bool addReference(Program* program, Instruction* instr, int opIndex,
                               const AddressSpace* space, Scalar* scalar);
    bool checkOffcutFuncRef(Program* program, const Address& addr);
    bool isValidRelocationAddress(Program* program, const Address& target);

    static constexpr int MAX_NEG_ENTRIES = 32;
    int alignment_ = 4;
    bool relocationGuideEnabled_ = false;

private:
    void checkForJumpTable(Program* program, Instruction* refInstr, int opIndex,
                            const std::vector<Scalar*>& opObjects, const Address& addr);
};

} // namespace ghidra
