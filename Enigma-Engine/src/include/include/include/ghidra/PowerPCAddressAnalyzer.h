#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <unordered_set>

namespace ghidra {

class Program;
class SymbolicPropogator;
class TaskMonitor;
class Instruction;
class Register;
class RegisterValue;
class VarnodeContext;

class PowerPCAddressAnalyzer : public ConstantPropagationAnalyzer {
public:
    PowerPCAddressAnalyzer();
    ~PowerPCAddressAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

protected:
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

public:
    bool markupDualInstructionOption = false;
    bool checkHighNibbleOption = false;
    bool propagateR2value = false;
    bool propagateR30value = false;
    bool recoverSwitchTables = true;

    void markupDualInstructions(VarnodeContext* context, Instruction* instr, Program* program);
    AddressSet recoverSwitches(Program* program, SymbolicPropogator* symEval,
                                const AddressSetView& destinationSet, TaskMonitor* monitor);
    bool checkAlreadyRecovered(Program* program, const Address& addr);
    void setRegisterIfNotSet(Program* program, const Address& addr, RegisterValue* regValue);
    bool isPEFCallingConvention(Program* program, Instruction* instr);

private:
    RegisterValue* lookupR2(Program* program, const Address& flowStart);
    RegisterValue* findR2Value(Program* program, const Address& start);
    RegisterValue* findPefR2Value(Program* program, const Address& start);
    void createDataType(Program* program, Instruction* instr, const Address& address);
    void labelTable(Program* program, const Address& loc,
                    const std::vector<Address>& targets);
    bool getDefaultPropagateR2Option(Program* program);
    bool getDefaultPropagateR30Option(Program* program);
};

} // namespace ghidra
