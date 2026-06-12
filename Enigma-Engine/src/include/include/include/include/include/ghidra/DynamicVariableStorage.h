#pragma once

#include <ghidra/VariableStorage.h>
#include <ghidra/AutoParameterType.h>
#include <optional>
#include <vector>
#include <string>

namespace ghidra {

class DynamicVariableStorage : public VariableStorage {
public:
    static const DynamicVariableStorage INDIRECT_VOID_STORAGE;

    // Constructors
    DynamicVariableStorage(Program* program, std::optional<AutoParameterType> autoParamType, Address address, int size);
    DynamicVariableStorage(Program* program, std::optional<AutoParameterType> autoParamType, const std::vector<Varnode>& varnodes);
    DynamicVariableStorage(Program* program, bool forcedIndirect, Address address, int size);
    DynamicVariableStorage(Program* program, bool forcedIndirect, const std::vector<Varnode>& varnodes);

    bool isForcedIndirect() const override;
    bool isAutoStorage() const override;
    bool isUnassignedStorage() const override;
    bool isVoidStorage() const override;
    AutoParameterType getAutoParameterType() const override;

    std::string toString() const override;

    static DynamicVariableStorage getUnassignedDynamicStorage(std::optional<AutoParameterType> autoParamType);
    static DynamicVariableStorage getUnassignedDynamicStorage(bool forcedIndirect);

private:
    // Private constructors
    DynamicVariableStorage(); // Constructs INDIRECT_VOID_STORAGE
    DynamicVariableStorage(std::optional<AutoParameterType> autoParamType);
    DynamicVariableStorage(bool forcedIndirect);

    std::optional<AutoParameterType> autoParamType_;
    bool forcedIndirect_ = false;
    bool isUnassigned_ = false;
    bool isVoid_ = false;
};

} // namespace ghidra
