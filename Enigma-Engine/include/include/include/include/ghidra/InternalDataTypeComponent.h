#pragma once

#include <ghidra/DataTypeComponent.h>
#include <string>

namespace ghidra {

class InternalDataTypeComponent : public virtual DataTypeComponent {
public:
    virtual void setDataType(DataType* dataType) = 0;
    virtual void update(int ordinal, int offset, int length) = 0;

    static std::string toString(const DataTypeComponent* c);
    static std::string cleanupFieldName(const std::string& name);
};

} // namespace ghidra
