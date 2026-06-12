#pragma once

#include <ghidra/AddressSpace.h>
#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <stdexcept>

namespace ghidra {

class AddressXML {
public:
    static constexpr int MAX_PIECES = 64;

    AddressXML() : space_(nullptr), offset_(0), size_(0) {}

    AddressXML(AddressSpace* spc, long off, int sz)
        : space_(spc), offset_(off), size_(sz) {}

    AddressXML(AddressSpace* spc, long off, int sz, const std::vector<Address>& /*pieces*/)
        : space_(spc), offset_(off), size_(sz) {}

    AddressSpace* getAddressSpace() const { return space_; }
    long getOffset() const { return offset_; }
    long getSize() const { return size_; }

    Address getFirstAddress() const {
        if (!space_) throw std::runtime_error("AddressXML: no address space");
        return Address(space_, offset_);
    }

    Address getLastAddress() const {
        if (!space_) throw std::runtime_error("AddressXML: no address space");
        return Address(space_, offset_ + size_ - 1);
    }

private:
    AddressSpace* space_;
    long offset_;
    long size_;
};

} // namespace ghidra
