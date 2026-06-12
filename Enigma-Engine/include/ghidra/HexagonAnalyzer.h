#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class HexagonAnalyzer : public ConstantPropagationAnalyzer {
public:
    HexagonAnalyzer();
    ~HexagonAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    AddressSet flowConstants(Program* program, const Address& flowStart,
                             const AddressSetView* flowSet, SymbolicPropogator* symEval,
                             TaskMonitor* monitor) override;

private:
    Register* r25Register_ = nullptr;
    Register* lrRegister_ = nullptr;
    Register* lrNewRegister_ = nullptr;
};

} // namespace ghidra
