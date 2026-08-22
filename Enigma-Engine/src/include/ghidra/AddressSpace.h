/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AddressSpace.h
/// \brief Abstract interface for address spaces
#pragma once

#include <cstdint>
#include <string>

namespace ghidra {

class Address;

class AddressSpace {
public:
    static constexpr int TYPE_CONSTANT = 0;
    static constexpr int TYPE_RAM = 1;
    static constexpr int TYPE_CODE = 2;
    static constexpr int TYPE_UNIQUE = 3;
    static constexpr int TYPE_REGISTER = 4;
    static constexpr int TYPE_STACK = 5;
    static constexpr int TYPE_JOIN = 6;
    static constexpr int TYPE_OTHER = 7;
    static constexpr int TYPE_SYMBOL = 9;
    static constexpr int TYPE_EXTERNAL = 10;
    static constexpr int TYPE_VARIABLE = 11;
    static constexpr int TYPE_DELETED = 13;
    static constexpr int TYPE_UNKNOWN = 14;
    static constexpr int TYPE_NONE = 15;

    static constexpr int TYPE_IPTR_CONSTANT = TYPE_CONSTANT;
    static constexpr int TYPE_IPTR_INTERNAL = TYPE_UNIQUE;
    static constexpr int TYPE_IPTR_SPACEBASE = TYPE_STACK;

    static constexpr int ID_SIZE_MASK = 0x0070;
    static constexpr int ID_SIZE_SHIFT = 4;
    static constexpr int ID_TYPE_MASK = 0x000f;
    static constexpr int ID_UNIQUE_SHIFT = 7;

    virtual ~AddressSpace();
    AddressSpace() = default;

    virtual std::string getName() const = 0;
    virtual int getSpaceID() const = 0;
    virtual int getSize() const = 0;
    virtual int getAddressableUnitSize() const = 0;
    virtual int64_t getAddressableWordOffset(int64_t byteOffset) const = 0;
    virtual int getPointerSize() const = 0;
    virtual int getType() const = 0;
    virtual int getUnique() const = 0;
    virtual int64_t truncateOffset(int64_t byteOffset) const = 0;
    virtual int64_t truncateAddressableWordOffset(int64_t wordOffset) const = 0;
    virtual int64_t makeValidOffset(int64_t offset) const = 0;

    virtual bool isMemorySpace() const = 0;
    virtual bool isLoadedMemorySpace() const = 0;
    virtual bool isNonLoadedMemorySpace() const = 0;
    virtual bool isRegisterSpace() const = 0;
    virtual bool isVariableSpace() const = 0;
    virtual bool isStackSpace() const = 0;
    virtual bool isHashSpace() const = 0;
    virtual bool isExternalSpace() const = 0;
    virtual bool isUniqueSpace() const = 0;
    virtual bool isConstantSpace() const = 0;
    virtual bool hasMappedRegisters() const = 0;
    virtual bool showSpaceName() const = 0;
    virtual bool isOverlaySpace() const = 0;
    virtual bool hasSignedOffset() const = 0;
    virtual int64_t getMaxOffset() const = 0;
    virtual int64_t getMinOffset() const = 0;

    virtual AddressSpace* getPhysicalSpace() = 0;

    /// Create an Address with the given flat byte offset. Subclasses
    /// (notably SegmentedAddressSpace) override to return richer
    /// Address types. The default implementation in GenericAddressSpace
    /// returns a plain Address.
    virtual Address getAddress(int64_t byteOffset) const;

    /// Like getAddress but does not translate through overlay spaces.
    /// The default implementation in GenericAddressSpace just returns
    /// a plain Address(space, byteOffset).
    virtual Address getAddressInThisSpaceOnly(int64_t byteOffset) const;

    /// Parse the address from a string. Subclasses (SegmentedAddressSpace)
    /// override to support `seg:offset` notation. The default
    /// implementation parses the string as a hex decimal offset.
    virtual Address getAddress(const std::string& addrString, bool caseSensitive) const;

    virtual bool operator==(const AddressSpace& other) const {
        return getSpaceID() == other.getSpaceID();
    }
    virtual bool operator<(const AddressSpace& other) const {
        return getSpaceID() < other.getSpaceID();
    }

    static bool isValidName(const std::string& name) {
        if (name.empty()) return false;
        for (char c : name) {
            if (c == ':' || c <= 0x20) return false;
        }
        return true;
    }
};

class GenericAddressSpace : public AddressSpace {
private:
    std::string name_;
    int size_;
    int type_;
    int unique_;
    int spaceID_;
    int unitSize_;
    uint64_t offsetMask_;
    bool signed_;

protected:
    int64_t maxOffset_;
    int64_t minOffset_;

public:
    GenericAddressSpace(const std::string& name, int size, int type, int unique);
    GenericAddressSpace(const std::string& name, int size, int type, int unique,
                        int64_t minOffset, int64_t maxOffset);
    virtual ~GenericAddressSpace() = default;

    std::string getName() const override;
    int getSpaceID() const override;
    int getSize() const override;
    int getAddressableUnitSize() const override;
    int64_t getAddressableWordOffset(int64_t byteOffset) const override;
    int getPointerSize() const override;
    int getType() const override;
    int getUnique() const override;

    int64_t truncateOffset(int64_t byteOffset) const override;
    int64_t truncateAddressableWordOffset(int64_t wordOffset) const override;
    int64_t makeValidOffset(int64_t offset) const override;

    Address getAddress(int64_t byteOffset) const override;
    Address getAddressInThisSpaceOnly(int64_t byteOffset) const override;
    Address getAddress(const std::string& addrString, bool caseSensitive) const override;

    int64_t getMaxOffset() const override;
    int64_t getMinOffset() const override;

    bool isMemorySpace() const override;
    bool isLoadedMemorySpace() const override;
    bool isNonLoadedMemorySpace() const override;
    bool isRegisterSpace() const override;
    bool isVariableSpace() const override;
    bool isStackSpace() const override;
    bool isHashSpace() const override;
    bool isExternalSpace() const override;
    bool isUniqueSpace() const override;
    bool isConstantSpace() const override;
    bool hasMappedRegisters() const override;
    bool showSpaceName() const override;
    bool isOverlaySpace() const override;
    bool hasSignedOffset() const override;

    AddressSpace* getPhysicalSpace() override;
};

} // namespace ghidra
