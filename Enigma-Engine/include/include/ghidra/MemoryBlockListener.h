#pragma once

#include <ghidra/Address.h>
#include <ghidra/MemoryBlock.h>
#include <string>
#include <vector>

namespace ghidra {

class MemoryBlockListener {
public:
    virtual ~MemoryBlockListener() = default;

    virtual void nameChanged(MemoryBlock* block, const std::string& oldName,
                             const std::string& newName) = 0;
    virtual void commentChanged(MemoryBlock* block, const std::string& oldComment,
                                const std::string& newComment) = 0;
    virtual void readStatusChanged(MemoryBlock* block, bool isRead) = 0;
    virtual void writeStatusChanged(MemoryBlock* block, bool isWrite) = 0;
    virtual void executeStatusChanged(MemoryBlock* block, bool isExecute) = 0;
    virtual void sourceChanged(MemoryBlock* block, const std::string& oldSource,
                               const std::string& newSource) = 0;
    virtual void sourceOffsetChanged(MemoryBlock* block, long long oldOffset,
                                     long long newOffset) = 0;
    virtual void dataChanged(MemoryBlock* block, const Address& addr,
                             const std::vector<uint8_t>& oldData,
                             const std::vector<uint8_t>& newData) = 0;
};

} // namespace ghidra
