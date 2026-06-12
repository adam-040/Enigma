#pragma once
#include <ghidra/Variable.h>
#include <ghidra/AutoParameterType.h>

namespace ghidra {

class Parameter : virtual public Variable {
public:
    static constexpr const char* RETURN_NAME = "<RETURN>";
    static constexpr int RETURN_ORDINAL = -1;
    static constexpr int RETURN_ORIDINAL = -1; // Compatibility with Java typo
    static constexpr int UNASSIGNED_ORDINAL = -2;

    virtual ~Parameter() = default;

    virtual int getOrdinal() const = 0;
    virtual bool isAutoParameter() const = 0;
    virtual AutoParameterType getAutoParameterType() const = 0;
    virtual bool isForcedIndirect() const = 0;
    virtual DataType* getFormalDataType() const = 0;
};

} // namespace ghidra
