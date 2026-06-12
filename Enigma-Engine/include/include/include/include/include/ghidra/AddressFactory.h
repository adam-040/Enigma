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
/// \file AddressFactory.h
/// \brief Factory for creating and managing Address objects across address spaces
/// Translated from: ghidra.program.model.address.AddressFactory
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include "ghidra/Address.h"
#include "ghidra/AddressSpace.h"
#include "ghidra/AddressSetView.h"

namespace ghidra {

class AddressSetView;

/**
 * Factory for creating Address objects and managing address spaces.
 * Provides methods to parse address strings, lookup spaces by name/ID,
 * and create addresses in specific spaces.
 */
class AddressFactory {
public:
    virtual ~AddressFactory() = default;

    /// Create an address from string. Tries default space first, then all spaces.
    virtual std::optional<Address> getAddress(const std::string& addrString) const = 0;

    /// Generates all reasonable memory addresses from the given string.
    virtual std::vector<Address> getAllAddresses(const std::string& addrString) const = 0;

    /// Generates all reasonable memory addresses with case sensitivity control.
    virtual std::vector<Address> getAllAddresses(const std::string& addrString, bool caseSensitive) const = 0;

    /// Returns the default AddressSpace.
    virtual const AddressSpace* getDefaultAddressSpace() const = 0;

    /// Returns the array of all "physical" AddressSpaces.
    virtual std::vector<const AddressSpace*> getAddressSpaces() const = 0;

    /// Returns an array of all address spaces, including analysis spaces.
    virtual std::vector<const AddressSpace*> getAllAddressSpaces() const = 0;

    /// Returns the space with the given name or nullptr if none exists.
    virtual const AddressSpace* getAddressSpace(const std::string& name) const = 0;

    /// Returns the space with the given spaceID or nullptr if none exists.
    virtual const AddressSpace* getAddressSpace(int spaceID) const = 0;

    /// Returns the number of physical AddressSpaces.
    virtual int getNumAddressSpaces() const = 0;

    /// Tests if the given address is valid for at least one AddressSpace.
    virtual bool isValidAddress(const Address& addr) const = 0;

    /// Returns the index (old encoding) for the given address.
    virtual uint64_t getIndex(const Address& addr) const = 0;

    /// Gets the physical address space associated with the given address space.
    virtual const AddressSpace* getPhysicalSpace(const AddressSpace* space) const = 0;

    /// Returns an array of all the physical address spaces.
    virtual std::vector<const AddressSpace*> getPhysicalSpaces() const = 0;

    /// Get an address using the addressSpace with the given id and offset.
    virtual Address getAddress(int spaceID, uint64_t offset) const = 0;

    /// Returns the "constant" address space.
    virtual const AddressSpace* getConstantSpace() const = 0;

    /// Returns the "unique" address space.
    virtual const AddressSpace* getUniqueSpace() const = 0;

    /// Returns the "stack" address space.
    virtual const AddressSpace* getStackSpace() const = 0;

    /// Returns the "register" address space.
    virtual const AddressSpace* getRegisterSpace() const = 0;

    /// Returns an address in "constant" space with the given offset.
    virtual Address getConstantAddress(uint64_t offset) const = 0;

    /// Computes an address set from start and end that may span address spaces.
    virtual AddressSet getAddressSet(const Address& min, const Address& max) const = 0;

    /// Returns an addressSet containing all possible "real" addresses.
    virtual AddressSet getAddressSet() const = 0;

    /// Returns the address using the old encoding format.
    virtual Address oldGetAddressFromLong(uint64_t value) const = 0;

    /// Returns true if there is more than one memory address space.
    virtual bool hasMultipleMemorySpaces() const = 0;

    /// Determine if this factory contains stale overlay address space instances.
    virtual bool hasStaleOverlayCondition() const { return false; }

    bool operator==(const AddressFactory& other) const { return equals(other); }
    bool operator!=(const AddressFactory& other) const { return !equals(other); }

    virtual bool equals(const AddressFactory& other) const = 0;
};

} // namespace ghidra
