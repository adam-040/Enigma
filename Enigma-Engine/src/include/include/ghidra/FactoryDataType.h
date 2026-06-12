#pragma once

#include <ghidra/BuiltInDataType.h>

namespace ghidra {

class MemBuffer;

class FactoryDataType : public virtual BuiltInDataType {
public:
    virtual DataType* getDataType(MemBuffer* buf) = 0;
    int getLength() const override { return -1; }
};

} // namespace ghidra
