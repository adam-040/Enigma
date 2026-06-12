#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <ghidra/DataType.h>
#include <ghidra/FunctionSignatureImpl.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace ghidra {

class ApplyKnownSignatureAnalyzer : public AbstractAnalyzer {
public:
    ApplyKnownSignatureAnalyzer();
    ~ApplyKnownSignatureAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;

    static std::unordered_map<std::string, FunctionSignatureImpl*>& getSignatureTable();

private:
    struct KnownSigEntry {
        const char* retType;
        std::vector<const char*> paramTypes;
        bool varargs;
        bool noreturn;
        const char* callingConvention;
    };
    static std::unordered_map<std::string, FunctionSignatureImpl*> signatureTable_;
    void ensureSignatureTable(DataTypeManager* dtm);
    DataType* resolveType(DataTypeManager* dtm, const std::string& name);
    ParameterDefinition* makeParameter(DataTypeManager* dtm, const char* typeName, const std::string& paramName, int ordinal);
};

} // namespace ghidra
