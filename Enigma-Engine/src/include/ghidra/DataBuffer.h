#pragma once

#include <ghidra/Data.h>
#include <ghidra/Address.h>
#include <vector>

namespace ghidra {

class DataBuffer {
public:
    virtual ~DataBuffer() = default;

    virtual Data* getData(int offset) = 0;
    virtual Data* getDataAfter(int offset) = 0;
    virtual Data* getDataBefore(int offset) = 0;
    virtual int getNextOffset(int offset) = 0;
    virtual int getPreviousOffset(int offset) = 0;
    virtual std::vector<Data*> getData(int start, int end) = 0;
    virtual Address getAddress() const = 0;
};

} // namespace ghidra
