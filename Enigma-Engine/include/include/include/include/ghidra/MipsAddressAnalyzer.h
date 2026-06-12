#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <ghidra/VarnodeContext.h>
#include <string>
#include <unordered_set>

namespace ghidra {

class Program;
class SymbolicPropogator;
class TaskMonitor;
class Instruction;
class Register;
class Symbol;

class MipsAddressAnalyzer : public ConstantPropagationAnalyzer {
public:
    MipsAddressAnalyzer();
    ~MipsAddressAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

protected:
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

public:
    // Configuration options (accessed by evaluator)
    bool trySwitchTables = false;
    bool markupDualInstructionOption = false;
    bool assumeT9EntryAddress = true;
    bool discoverGlobalGPSetting = true;

    std::unordered_set<std::string> targetLoadStore = {
        "addiu", "daddiu", "lw", "_lw", "sw", "_sw", "sh", "_sh", "sd", "_sd", "lbu", "lhu"
    };

    Register* t9 = nullptr;
    Register* gp = nullptr;
    Register* rareg = nullptr;
    Register* isamode = nullptr;
    Register* ismbit = nullptr;
    Address gp_assumption_value{};

    void checkForGlobalGP(Program* program, const AddressSetView& set, TaskMonitor* monitor);
    Symbol* setGPSymbol(Program* program, const Address& toAddr);
    void markupDualInstructions(VarnodeContext* context, Instruction* instr, Program* program);
    Address mipsExtDisassembly(Program* program, Instruction* instruction, VarnodeContext* context,
                                const Address& target, TaskMonitor* monitor);
    Address flowISA(Program* program, Instruction* instruction, VarnodeContext* context,
                     const Address& target);
    void fixJumpTable(Program* program, Instruction* startInstr, TaskMonitor* monitor);
    bool checkAlreadyRecovered(Program* program, const Address& addr);

private:
    static constexpr int MAX_UNIQUE_GP_SYMBOLS = 50;
};

} // namespace ghidra
