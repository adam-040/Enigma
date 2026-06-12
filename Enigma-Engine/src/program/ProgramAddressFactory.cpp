/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramAddressFactory.cpp
/// \brief Address factory for programs with overlay support
/// Translated from: ghidra.program.database.ProgramAddressFactory

#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

std::optional<Address> ProgramAddressFactory::getAddress(const std::string& addrStr) const {
    if (!addrStr.empty()) {
        // Handle Stack[...] format (case insensitive prefix)
        if (addrStr.find("Stack[") == 0 || addrStr.find("stack[") == 0) {
            size_t startBracket = addrStr.find('[');
            size_t endBracket = addrStr.find(']');
            if (startBracket != std::string::npos && endBracket != std::string::npos && endBracket > startBracket + 1) {
                std::string offsetStr = addrStr.substr(startBracket + 1, endBracket - startBracket - 1);
                bool negative = false;
                if (!offsetStr.empty() && offsetStr[0] == '-') {
                    negative = true;
                    offsetStr = offsetStr.substr(1);
                }
                try {
                    uint64_t val = std::stoull(offsetStr, nullptr, 16);
                    int64_t offset = static_cast<int64_t>(val);
                    if (negative) {
                        offset = -offset;
                    }
                    for (auto* space : addressSpaces_) {
                        if (space && space->isStackSpace()) {
                            return Address(space, offset);
                        }
                    }
                    if (stackSpace_) {
                        return Address(stackSpace_, offset);
                    }
                } catch (...) {
                    return std::nullopt;
                }
            }
        }

        for (auto* space : addressSpaces_) {
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

std::vector<Address> ProgramAddressFactory::getAllAddresses(const std::string& addrStr) const {
    std::vector<Address> result;
    auto addr = getAddress(addrStr);
    if (addr.has_value()) result.push_back(addr.value());
    return result;
}

std::vector<Address> ProgramAddressFactory::getAllAddresses(const std::string& addrStr, bool caseSensitive) const {
    return getAllAddresses(addrStr);
}

std::vector<const AddressSpace*> ProgramAddressFactory::getAddressSpaces() const {
    std::vector<const AddressSpace*> result;
    for (auto* space : addressSpaces_) result.push_back(space);
    return result;
}

std::vector<const AddressSpace*> ProgramAddressFactory::getAllAddressSpaces() const {
    return getAddressSpaces();
}

const AddressSpace* ProgramAddressFactory::getAddressSpace(const std::string& name) const {
    for (auto* space : addressSpaces_) {
        if (space->getName() == name) return space;
    }
    return nullptr;
}

const AddressSpace* ProgramAddressFactory::getAddressSpace(int spaceID) const {
    for (auto* space : addressSpaces_) {
        if (space->getSpaceID() == spaceID) return space;
    }
    return nullptr;
}

bool ProgramAddressFactory::isValidAddress(const Address& addr) const {
    if (!addr.getAddressSpace()) return false;
    for (auto* space : addressSpaces_) {
        if (space == addr.getAddressSpace()) return true;
    }
    return false;
}

Address ProgramAddressFactory::getAddress(int spaceID, uint64_t offset) const {
    for (auto* space : addressSpaces_) {
        if (space->getSpaceID() == spaceID) return Address(space, static_cast<long>(offset));
    }
    return Address();
}

Address ProgramAddressFactory::getConstantAddress(uint64_t offset) const {
    if (constantSpace_) return Address(constantSpace_, static_cast<long>(offset));
    return Address();
}

AddressSet ProgramAddressFactory::getAddressSet(const Address& min, const Address& max) const {
    AddressSet tmpSet;
    if (min.getAddressSpace() && max.getAddressSpace()) {
        tmpSet.addRange(min, max);
    }
    return tmpSet;
}

AddressSet ProgramAddressFactory::getAddressSet() const {
    return AddressSet();
}

bool ProgramAddressFactory::hasMultipleMemorySpaces() const {
    int count = 0;
    for (auto* space : addressSpaces_) {
        if (space->getType() == AddressSpace::TYPE_RAM) count++;
    }
    return count > 1;
}

bool ProgramAddressFactory::equals(const AddressFactory& other) const {
    const auto* paf = dynamic_cast<const ProgramAddressFactory*>(&other);
    if (!paf) return false;
    return addressSpaces_ == paf->addressSpaces_;
}

Address ProgramAddressFactory::parseAddressWithSpace(const std::string& addrStr, AddressSpace* space) const {
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
        return Address(space, static_cast<long>(offset));
    } catch (...) {
        return Address();
    }
}

} // namespace ghidra
