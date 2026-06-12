#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <string>

namespace ghidra {

class SymbolTable;
class Symbol;

class ArmSymbolAnalyzer : public AbstractAnalyzer {
public:
    ArmSymbolAnalyzer();
    ~ArmSymbolAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool getDefaultEnablement(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void analysisEnded(Program* program) override;

private:
    void setTModeRegister(Program* program, const Address& newAddress);
    void updateEntryPoint(Program* program, const Address& address, const Address& newAddress);
    void moveSymbols(Program* program, const Address& address, const Address& newAddress);
    void moveFunction(Program* program, const Address& address, const Address& newAddress);
    void createLabel(SymbolTable* symbolTable, const Address& address, const std::string& name, SourceType sourceType);
};

} // namespace ghidra
