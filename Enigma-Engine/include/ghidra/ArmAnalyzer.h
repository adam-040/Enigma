#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <string>

namespace ghidra {

class Program;
class SymbolicPropogator;
class TaskMonitor;
class Instruction;
class Register;
class VarnodeContext;

class ArmAnalyzer : public ConstantPropagationAnalyzer {
public:
    ArmAnalyzer();
    ~ArmAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

protected:
    void optionsChanged(Options& options, Program* program) override;

public:
    bool recoverSwitchTables = false;

    Register* tbRegister = nullptr;
    Register* tmodeRegister = nullptr;
    Register* lrRegister = nullptr;

    static constexpr long MAX_DISTANCE = (4 * 1024);

    bool hasDataReferenceTo(Program* program, const Address& addr);
    AddressSet recoverSwitches(Program* program, const AddressSetView& destSet,
                                SymbolicPropogator* symEval, TaskMonitor* monitor);
    int createDataType(Instruction* instr, const Address& address);
    Address flowArmThumb(Program* program, Instruction* instruction, VarnodeContext* context,
                          const Address& target, FlowType* flowType, bool addReference);
    void doArmThumbDisassembly(Program* program, Instruction* instruction, VarnodeContext* context,
                                const Address& target, FlowType* flowType, bool addRef,
                                TaskMonitor* monitor);

private:
    static constexpr long SWITCH_TABLE_MAX_SIZE = 64;
};

} // namespace ghidra
