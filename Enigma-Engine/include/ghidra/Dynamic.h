#pragma once

#include <ghidra/BuiltInDataType.h>

namespace ghidra {

class MemBuffer;

class Dynamic : public virtual BuiltInDataType {
public:
    virtual int getLength(MemBuffer* buf, int maxLength) = 0;
    virtual bool canSpecifyLength() { return false; }
    virtual DataType* getReplacementBaseType() = 0;
};

} // namespace ghidra
