#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class Register;

class MipsPreAnalyzer : public AbstractAnalyzer {
public:
    MipsPreAnalyzer();
    ~MipsPreAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

private:
    AddressSet removeUninitializedBlock(Program* program, const AddressSetView& set);
    bool checkPossiblePairInstruction(Program* program, Address addr);
    bool skipif16orR6(Program* program, Instruction* instr);
    void findPair(Program* program, AddressSet& pairSet, Instruction* start_inst, TaskMonitor* monitor);

    Register* pairBitRegister_ = nullptr;
    Register* isamode_ = nullptr;
    Register* ismbit_ = nullptr;
    Register* rel6bit_ = nullptr;
    Register* micro16bit_ = nullptr;
};

} // namespace ghidra
