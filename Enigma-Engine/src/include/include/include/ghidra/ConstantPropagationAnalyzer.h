#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <string>

namespace ghidra {

class SymbolicPropogator;
class TaskMonitor;
class Program;
class AddressSetView;

class ConstantPropagationAnalyzer : public AbstractAnalyzer {
public:
    ConstantPropagationAnalyzer();
    explicit ConstantPropagationAnalyzer(const std::string& processorName);

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

    virtual AddressSet flowConstants(Program* program, const Address& flowStart,
                                     const AddressSetView* flowSet, SymbolicPropogator* symEval,
                                     TaskMonitor* monitor);

protected:
    std::string processorName_;

    bool checkParamRefsOption = true;
    bool checkPointerParamRefsOption = false;
    bool checkStoredRefsOption = true;
    bool trustWriteMemOption = true;
    bool createComplexDataFromPointers = false;
    long minStoreLoadRefAddress = 4;
    long minSpeculativeRefAddress = 1024;
    long maxSpeculativeRefAddress = 256;

    void checkInstruction(Program* program, Instruction* instr, Memory* memory);
    void handleCopyConstant(Program* program, Instruction* instr, PcodeOp* op);
    void handleAddConstant(Program* program, Instruction* instr, PcodeOp* op);
    bool isValidAddress(Program* program, Memory* memory, const Address& addr);
};

} // namespace ghidra
