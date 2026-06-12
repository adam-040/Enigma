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
/// \file Register.cpp
/// \brief Processor register implementation
#include <ghidra/Register.h>

namespace ghidra {

void Register::updateBaseRegisterInfo() {
    baseRegister_ = parent_->getBaseRegister();
    baseMask_.clear();
    int baseStartAddr = baseRegister_->getOffset();
    int baseEndAddr = baseStartAddr + baseRegister_->numBytes_;
    int myStartAddr = getOffset();
    int myEndAddr = myStartAddr + numBytes_;

    if (bigEndian_) {
        int bytesAfterMe = baseEndAddr - myEndAddr;
        leastSigBitInBaseRegister_ = leastSigBit_ + bytesAfterMe * 8;
    }
    else {
        int bytesBeforeMe = myStartAddr - baseStartAddr;
        leastSigBitInBaseRegister_ = leastSigBit_ + bytesBeforeMe * 8;
    }

    for (auto* child : childRegisters_) {
        child->updateBaseRegisterInfo();
    }
}

void Register::setBit(std::vector<uint8_t>& byteMask, int bit) const {
    int byteNum = static_cast<int>(byteMask.size()) - (bit / 8) - 1;
    int bitNum = bit % 8;
    byteMask[byteNum] |= static_cast<uint8_t>(1 << bitNum);
}

Register::Register(const std::string& name, const std::string& description, const Address& address,
                   int numBytes, int leastSignificantBit, int bitLength, bool bigEndian, int typeFlags)
    : name_(name), description_(description), address_(address), numBytes_(numBytes),
      leastSigBit_(leastSignificantBit), bitLength_(bitLength), typeFlags_(typeFlags),
      bigEndian_(bigEndian)
{
    int leastSigByte = leastSignificantBit / 8;
    int mostSigByte = (leastSignificantBit + bitLength - 1) / 8;
    int extraLowerBytes = leastSigByte;
    int extraHighBytes = numBytes - mostSigByte - 1;

    if (bigEndian) {
        if (extraLowerBytes > 0) {
            this->numBytes_ = numBytes - extraLowerBytes;
            this->leastSigBit_ -= extraLowerBytes * 8;
        }
        if (extraHighBytes > 0) {
            this->address_ = address.add(extraHighBytes);
            this->numBytes_ -= extraHighBytes;
        }
    }
    else {
        if (extraLowerBytes > 0) {
            this->address_ = address.add(extraLowerBytes);
            this->numBytes_ -= extraLowerBytes;
            this->leastSigBit_ -= extraLowerBytes * 8;
        }
        if (extraHighBytes > 0) {
            this->numBytes_ -= extraHighBytes;
        }
    }
}

Register::Register(const std::string& name, const std::string& description, const Address& address,
                   int numBytes, bool bigEndian, int typeFlags)
    : Register(name, description, address, numBytes, 0, numBytes * 8, bigEndian, typeFlags) {}

Register::Register(const Register& other)
    : Register(other.name_, other.description_, other.address_, other.numBytes_,
               other.leastSigBit_, other.bitLength_, other.bigEndian_, other.typeFlags_) {}

void Register::addAlias(const std::string& alias) {
    if (name_ == alias) return;
    aliases_.insert(alias);
}

void Register::removeAlias(const std::string& alias) {
    aliases_.erase(alias);
}

void Register::setParent(Register* parent) {
    parent_ = parent;
    updateBaseRegisterInfo();
    for (auto* child : childRegisters_) {
        child->updateBaseRegisterInfo();
    }
}

void Register::setChildRegisters(const std::vector<Register*>& children) {
    for (auto* reg : children) {
        if (reg->isProcessorContext()) {
            typeFlags_ |= TYPE_CONTEXT;
        }
        reg->setParent(this);
    }
    childRegisters_ = children;
    std::sort(childRegisters_.begin(), childRegisters_.end(),
        [](const Register* a, const Register* b) {
            return a->getLeastSignificantBit() < b->getLeastSignificantBit();
        });
}

const std::vector<uint8_t>& Register::getBaseMask() {
    if (baseMask_.empty()) {
        Register* base = getBaseRegister();
        int byteLength = (base->getBitLength() + 7) / 8;
        baseMask_.resize(byteLength, 0);
        int endBit = leastSigBitInBaseRegister_ + bitLength_ - 1;
        for (int i = leastSigBitInBaseRegister_; i <= endBit; i++) {
            setBit(baseMask_, i);
        }
    }
    return baseMask_;
}

bool Register::contains(const Register& reg) const {
    if (*this == reg) return true;
    for (auto* child : childRegisters_) {
        if (child->contains(reg)) return true;
    }
    return false;
}

void Register::rename(const std::string& newName) {
    aliases_.erase(newName);
    name_ = newName;
}

bool Register::isValidLaneSize(int laneSizeInBytes) const {
    if (!isVectorRegister()) return false;
    if (laneSizeInBytes > 64 || laneSizeInBytes < 1) return false;
    return (((static_cast<uint64_t>(1) << (laneSizeInBytes - 1)) & laneSizes_) != 0);
}

std::vector<int> Register::getLaneSizes() const {
    if (laneSizes_ == 0) return {};
    std::vector<int> sizes;
    int size = 1;
    uint64_t tmp = laneSizes_;
    while (tmp != 0) {
        if ((tmp & 1) != 0) sizes.push_back(size);
        tmp >>= 1;
        size += 1;
    }
    return sizes;
}

void Register::addLaneSize(int laneSizeInBytes) {
    if ((8 * numBytes_) != bitLength_) {
        throw std::runtime_error("Register " + name_ + " does not support lanes");
    }
    if (laneSizeInBytes <= 0 || laneSizeInBytes >= numBytes_ || laneSizeInBytes > 64 ||
        (numBytes_ % laneSizeInBytes) != 0) {
        throw std::invalid_argument("Invalid lane size: " + std::to_string(laneSizeInBytes));
    }
    typeFlags_ |= TYPE_VECTOR;
    laneSizes_ |= (static_cast<uint64_t>(1) << (laneSizeInBytes - 1));
}

int Register::compareTo(const Register& other) const {
    int result;
    if (*getBaseRegister() == *other.getBaseRegister()) {
        result = leastSigBitInBaseRegister_ - other.leastSigBitInBaseRegister_;
    }
    else {
        result = (address_ < other.address_) ? -1 : (other.address_ < address_ ? 1 : 0);
    }
    if (result == 0) {
        result = bitLength_ - other.bitLength_;
    }
    return result;
}

std::string Register::toString() const { return name_; }

} // namespace ghidra
