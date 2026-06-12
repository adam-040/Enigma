/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file Register.h
/// \brief Class to represent a processor register
/// Translated from: ghidra.program.model.lang.Register
#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include "ghidra/Address.h"

namespace ghidra {

/**
 * Class to represent a processor register. To handle bit registers, a special addressing
 * convention is used: upper bit set, next 3 bits for bit position within a byte,
 * rest of address is the byte address where the register bit lives.
 */
class Register {
public:
    static constexpr int TYPE_NONE = 0;
    static constexpr int TYPE_FP = 1;
    static constexpr int TYPE_SP = 2;
    static constexpr int TYPE_PC = 4;
    static constexpr int TYPE_CONTEXT = 8;
    static constexpr int TYPE_ZERO = 16;
    static constexpr int TYPE_HIDDEN = 32;
    static constexpr int TYPE_DOES_NOT_FOLLOW_FLOW = 64;
    static constexpr int TYPE_VECTOR = 128;

private:
    std::string name_;
    std::string description_;
    Address address_;
    int numBytes_;
    int leastSigBit_;
    int bitLength_;
    int typeFlags_;
    bool bigEndian_;
    std::vector<Register*> childRegisters_;
    std::set<std::string> aliases_;
    std::vector<uint8_t> baseMask_;
    int leastSigBitInBaseRegister_ = 0;
    Register* parent_ = nullptr;
    Register* baseRegister_ = nullptr;
    std::string group_;
    uint64_t laneSizes_ = 0;

    void updateBaseRegisterInfo();
    void setBit(std::vector<uint8_t>& byteMask, int bit) const;

public:
    /// Full constructor with bit-level control
    Register(const std::string& name, const std::string& description, const Address& address,
             int numBytes, int leastSignificantBit, int bitLength, bool bigEndian, int typeFlags);
    Register(const std::string& name, const std::string& description, const Address& address,
             int numBytes, bool bigEndian, int typeFlags);
    Register(const Register& other);

    void addAlias(const std::string& alias);
    void removeAlias(const std::string& alias);

    const std::set<std::string>& getAliases() const { return aliases_; }

    const std::string& getName() const { return name_; }
    const std::string& getDescription() const { return description_; }
    bool isBigEndian() const { return bigEndian_; }
    int getBitLength() const { return bitLength_; }

    int getMinimumByteSize() const { return (bitLength_ + 7) / 8; }
    int getNumBytes() const { return numBytes_; }
    int getOffset() const { return static_cast<int>(address_.getOffset()); }
    int getLeastSignificantBit() const { return leastSigBit_; }

    bool isDefaultFramePointer() const { return (typeFlags_ & TYPE_FP) != 0; }
    bool followsFlow() const { return (typeFlags_ & TYPE_DOES_NOT_FOLLOW_FLOW) == 0; }
    bool isHidden() const { return (typeFlags_ & TYPE_HIDDEN) != 0; }
    bool isProgramCounter() const { return (typeFlags_ & TYPE_PC) != 0; }
    bool isProcessorContext() const { return (typeFlags_ & TYPE_CONTEXT) != 0; }
    bool isZero() const { return (typeFlags_ & TYPE_ZERO) != 0; }
    bool isVectorRegister() const { return (typeFlags_ & TYPE_VECTOR) != 0; }

    AddressSpace* getAddressSpace() const { return address_.getAddressSpace(); }
    const Address& getAddress() const { return address_; }

    Register* getParentRegister() const { return parent_; }

    std::vector<Register*> getChildRegisters() const { return childRegisters_; }

    Register* getBaseRegister() const {
        return baseRegister_ ? baseRegister_ : const_cast<Register*>(this);
    }

    int getLeastSignificantBitInBaseRegister() const { return leastSigBitInBaseRegister_; }

    void setParent(Register* parent);
    void setChildRegisters(const std::vector<Register*>& children);

    int getTypeFlags() const { return typeFlags_; }

    const std::vector<uint8_t>& getBaseMask();

    void setFlag(int flag) { typeFlags_ |= flag; }

    bool hasChildren() const { return !childRegisters_.empty(); }

    void setGroup(const std::string& group) { group_ = group; }
    const std::string& getGroup() const { return group_; }

    bool isBaseRegister() const { return baseRegister_ == nullptr; }

    bool contains(const Register& reg) const;
    void rename(const std::string& newName);
    bool isValidLaneSize(int laneSizeInBytes) const;
    std::vector<int> getLaneSizes() const;
    void addLaneSize(int laneSizeInBytes);

    bool operator==(const Register& other) const {
        return name_ == other.name_ && bitLength_ == other.bitLength_ &&
               address_ == other.address_ && leastSigBit_ == other.leastSigBit_;
    }

    bool operator!=(const Register& other) const { return !(*this == other); }

    int compareTo(const Register& other) const;
    bool operator<(const Register& other) const { return compareTo(other) < 0; }
    std::string toString() const;
};

} // namespace ghidra
