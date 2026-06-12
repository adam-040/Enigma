#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressRange.h>
#include <ghidra/MemoryBlock.h>
#include <string>
#include <optional>

namespace ghidra {

// Forward declarations for types not yet ported
class ByteMappingScheme;
class FileBytes;

class MemoryBlockSourceInfo {
public:
    virtual ~MemoryBlockSourceInfo() = default;

    virtual long long getLength() const = 0;
    virtual Address getMinAddress() const = 0;
    virtual Address getMaxAddress() const = 0;
    virtual std::string getDescription() const = 0;

    virtual std::optional<FileBytes*> getFileBytes() const = 0;
    virtual long long getFileBytesOffset() const = 0;
    virtual long long getFileBytesOffset(const Address& address) const = 0;

    virtual std::optional<AddressRange> getMappedRange() const = 0;
    virtual std::optional<ByteMappingScheme*> getByteMappingScheme() const = 0;

    virtual MemoryBlock* getMemoryBlock() const = 0;
    virtual bool contains(const Address& address) const = 0;

    bool containsFileOffset(long long fileOffset) const {
        long long startOffset = getFileBytesOffset();
        if (startOffset < 0 || fileOffset < 0) {
            return false;
        }
        long long endOffset = startOffset + (getLength() - 1);
        return (fileOffset >= startOffset) && (fileOffset <= endOffset);
    }

    Address locateAddressForFileOffset(long long fileOffset) const {
        long long startOffset = getFileBytesOffset();
        if (!containsFileOffset(fileOffset)) {
            return Address();
        }
        long long offset = fileOffset - startOffset;
        if (offset >= getLength()) {
            return Address();
        }
        return getMinAddress().add(offset);
    }
};

} // namespace ghidra
