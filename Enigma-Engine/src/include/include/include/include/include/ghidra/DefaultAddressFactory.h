/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

class DefaultAddressFactory : public AddressFactory {
private:
    std::vector<const AddressSpace*> spaces_;
    const AddressSpace* defaultSpace_ = nullptr;
    const AddressSpace* constantSpace_ = nullptr;
    const AddressSpace* uniqueSpace_ = nullptr;
    const AddressSpace* registerSpace_ = nullptr;
    const AddressSpace* stackSpace_ = nullptr;

    Address parseAddressWithSpace(const std::string& addrStr, const AddressSpace* space) const {
        std::string offsetStr = addrStr;
        size_t colonPos = addrStr.find(':');
        if (colonPos != std::string::npos) {
            offsetStr = addrStr.substr(colonPos + 1);
            if (!offsetStr.empty() && offsetStr[0] == ':') {
                offsetStr = offsetStr.substr(1);
            }
        }
        try {
            uint64_t offset = std::stoull(offsetStr, nullptr, 16);
            return Address(const_cast<AddressSpace*>(space), static_cast<int64_t>(offset));
        } catch (...) {
            return Address();
        }
    }

public:
    DefaultAddressFactory() = default;

    DefaultAddressFactory(const std::vector<const AddressSpace*>& addrSpaces, const AddressSpace* defaultSpace = nullptr) {
        spaces_ = addrSpaces;
        for (const auto* space : addrSpaces) {
            if (space == defaultSpace) {
                defaultSpace_ = space;
            }
            if (space->getType() == AddressSpace::TYPE_CONSTANT) {
                constantSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_UNIQUE) {
                uniqueSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_REGISTER) {
                registerSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_STACK) {
                stackSpace_ = space;
            }
        }

        if (!defaultSpace_ && !spaces_.empty()) {
            defaultSpace_ = spaces_[0];
        }
    }

    virtual ~DefaultAddressFactory() override = default;

    std::optional<Address> getAddress(const std::string& addrStr) const override {
        if (!addrStr.empty()) {
            for (const auto* space : spaces_) {
                if (addrStr.find(space->getName()) == 0) {
                    return parseAddressWithSpace(addrStr, space);
                }
            }
            if (defaultSpace_) {
                return parseAddressWithSpace(addrStr, defaultSpace_);
            }
        }
        return std::nullopt;
    }

    std::vector<Address> getAllAddresses(const std::string& addrStr) const override {
        std::vector<Address> result;
        auto addr = getAddress(addrStr);
        if (addr.has_value()) {
            result.push_back(addr.value());
        }
        return result;
    }

    std::vector<Address> getAllAddresses(const std::string& addrStr, bool caseSensitive) const override {
        return getAllAddresses(addrStr);
    }

    const AddressSpace* getDefaultAddressSpace() const override {
        return defaultSpace_;
    }

    std::vector<const AddressSpace*> getAddressSpaces() const override {
        return spaces_;
    }

    std::vector<const AddressSpace*> getAllAddressSpaces() const override {
        return spaces_;
    }

    const AddressSpace* getAddressSpace(const std::string& name) const override {
        for (const auto* space : spaces_) {
            if (space->getName() == name) return space;
        }
        return nullptr;
    }

    const AddressSpace* getAddressSpace(int spaceID) const override {
        for (const auto* space : spaces_) {
            if (space->getSpaceID() == spaceID) return space;
        }
        return nullptr;
    }

    int getNumAddressSpaces() const override {
        return static_cast<int>(spaces_.size());
    }

    bool isValidAddress(const Address& addr) const override {
        if (!addr.getAddressSpace()) return false;
        for (const auto* space : spaces_) {
            if (space == addr.getAddressSpace()) return true;
        }
        return false;
    }

    uint64_t getIndex(const Address& addr) const override {
        return addr.getOffset();
    }

    const AddressSpace* getPhysicalSpace(const AddressSpace* space) const override {
        return space;
    }

    std::vector<const AddressSpace*> getPhysicalSpaces() const override {
        return spaces_;
    }

    Address getAddress(int spaceID, uint64_t offset) const override {
        const auto* space = getAddressSpace(spaceID);
        if (space) return Address(const_cast<AddressSpace*>(space), static_cast<int64_t>(offset));
        return Address();
    }

    const AddressSpace* getConstantSpace() const override {
        return constantSpace_;
    }

    const AddressSpace* getUniqueSpace() const override {
        return uniqueSpace_;
    }

    const AddressSpace* getStackSpace() const override {
        return stackSpace_;
    }

    const AddressSpace* getRegisterSpace() const override {
        return registerSpace_;
    }

    Address getConstantAddress(uint64_t offset) const override {
        if (constantSpace_) return Address(const_cast<AddressSpace*>(constantSpace_), static_cast<int64_t>(offset));
        return Address();
    }

    AddressSet getAddressSet(const Address& min, const Address& max) const override {
        AddressSet tmpSet;
        if (min.getAddressSpace() && max.getAddressSpace()) {
            tmpSet.addRange(min, max);
        }
        return tmpSet;
    }

    AddressSet getAddressSet() const override {
        return AddressSet();
    }

    Address oldGetAddressFromLong(uint64_t value) const override {
        if (defaultSpace_) return Address(const_cast<AddressSpace*>(defaultSpace_), static_cast<int64_t>(value));
        return Address();
    }

    bool hasMultipleMemorySpaces() const override {
        int count = 0;
        for (const auto* space : spaces_) {
            if (space->getType() == AddressSpace::TYPE_RAM) count++;
        }
        return count > 1;
    }

    bool equals(const AddressFactory& other) const override {
        const auto* daf = dynamic_cast<const DefaultAddressFactory*>(&other);
        if (!daf) return false;
        return spaces_ == daf->spaces_;
    }

    void addAddressSpace(const AddressSpace* space) {
        if (std::find(spaces_.begin(), spaces_.end(), space) == spaces_.end()) {
            spaces_.push_back(space);
            if (!defaultSpace_) defaultSpace_ = space;
            if (space->getType() == AddressSpace::TYPE_CONSTANT) {
                constantSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_UNIQUE) {
                uniqueSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_REGISTER) {
                registerSpace_ = space;
            } else if (space->getType() == AddressSpace::TYPE_STACK) {
                stackSpace_ = space;
            }
        }
    }

    void removeAddressSpace(const std::string& name) {
        auto it = std::remove_if(spaces_.begin(), spaces_.end(),
            [&name](const AddressSpace* s) { return s->getName() == name; });
        if (it != spaces_.end()) {
            const AddressSpace* removed = *it;
            spaces_.erase(it, spaces_.end());
            if (defaultSpace_ == removed) {
                defaultSpace_ = spaces_.empty() ? nullptr : spaces_[0];
            }
            if (constantSpace_ == removed) constantSpace_ = nullptr;
            if (uniqueSpace_ == removed) uniqueSpace_ = nullptr;
            if (registerSpace_ == removed) registerSpace_ = nullptr;
            if (stackSpace_ == removed) stackSpace_ = nullptr;
        }
    }
};

} // namespace ghidra
