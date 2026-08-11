#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <vector>
#include <memory>

namespace ghidra {

class PcodeOp;
class Language;
class DataType;

class Varnode {
public:
    struct Join {
        std::vector<Varnode*> pieces;
        int logicalSize;
    };

    Varnode(Address a, int sz) 
        : address(a), size(sz) {
        spaceID = a.getAddressSpace() ? a.getAddressSpace()->getSpaceID() : 0;
        offset = a.getOffset();
    }

    Varnode(Address a, int sz, int symbolKey) : Varnode(a, sz) {}
    virtual ~Varnode() = default;

    int getSize() const { return size; }
    int getSpace() const { return spaceID; }
    Address getAddress() const { return address; }

    Address getPCAddress() const {
        if (isInput()) return Address();
        return Address();
    }

    long getOffset() const { return offset; }
    long getWordOffset() const { return address.getAddressableWordOffset(); }
    virtual bool isFree() const { return true; }

    bool contains(Address addr) const;
    bool intersects(const Varnode& vn) const;
    bool isContiguous(const Varnode& lo, bool bigEndian) const;

    bool isAddress() const {
        return (AddressSpace::ID_TYPE_MASK & spaceID) == AddressSpace::TYPE_RAM;
    }

    bool isRegister() const {
        return (AddressSpace::ID_TYPE_MASK & spaceID) == AddressSpace::TYPE_REGISTER;
    }

    bool isConstant() const {
        return (AddressSpace::ID_TYPE_MASK & spaceID) == AddressSpace::TYPE_CONSTANT;
    }

    bool isUnique() const {
        return (AddressSpace::ID_TYPE_MASK & spaceID) == AddressSpace::TYPE_UNIQUE;
    }

    bool isHash() const {
        return address.getAddressSpace()->getName() == "hash";
    }

    virtual bool isInput() const { return false; }
    virtual bool isPersistent() const { return false; }
    virtual bool isAddrTied() const { return false; }
    virtual bool isUnaffected() const { return false; }

    /// True if the Varnode is tagged volatile.
    virtual bool isVolatile() const { return false; }

    /// @return the DataType attached to this Varnode, or nullptr.
    virtual DataType* getDataType() const { return nullptr; }

    virtual PcodeOp* getDef() const { return nullptr; }

    /// Mark (or unmark) the Varnode volatile. The base implementation
    /// is a no-op; subclasses that carry the volatile flag override.
    virtual void setVolatile(bool /*val*/) {}

    /// Attach a data-type to this Varnode. The base implementation
    /// is a no-op; subclasses that carry a DataType override.
    virtual void setDataType(DataType* /*type*/) {}
    
    void trim();

    std::string toString() const {
        std::stringstream ss;
        ss << "(" << address.getAddressSpace()->getName() << ", 0x" 
           << std::hex << offset << ", " << std::dec << size << ")";
        return ss.str();
    }

    std::string toString(const Language& lang) const;

    bool operator==(const Varnode& other) const {
        if (!other.isFree()) return false;
        return (offset == other.offset && size == other.size && spaceID == other.spaceID);
    }

    bool operator!=(const Varnode& other) const { return !(*this == other); }

    size_t hash() const {
        return std::hash<long>{}(offset) ^ std::hash<int>{}(size) ^ std::hash<int>{}(spaceID);
    }

private:
    bool rangeIntersects(long otherOffset, long otherEndOffset) const;

    Address address;
    int size;
    int spaceID;
    long offset;
};

} // namespace ghidra
