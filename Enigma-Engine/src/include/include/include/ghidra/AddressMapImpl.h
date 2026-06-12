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

#include <ghidra/AddressMap.h>
#include <ghidra/KeyRange.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/OverlayAddressSpace.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>

namespace ghidra {

class AddressMapImpl : public AddressMap {
public:
    static constexpr int ADDR_OFFSET_SIZE = 32;
    static constexpr int MAP_ID_SIZE = 8;
    static constexpr uint64_t MAX_OFFSET = (1ULL << ADDR_OFFSET_SIZE) - 1;
    static constexpr uint64_t ADDR_OFFSET_MASK = MAX_OFFSET;
    static constexpr uint64_t MAP_ID_MASK = ~0ULL << (64 - MAP_ID_SIZE);

    static constexpr uint64_t BASE_MASK = ~ADDR_OFFSET_MASK;
    static constexpr int BASE_ID_SIZE = 64 - MAP_ID_SIZE - ADDR_OFFSET_SIZE;
    static constexpr int BASE_ID_MASK = (1 << BASE_ID_SIZE) - 1;

    static constexpr int STACK_SPACE_ID = 0x00FFFFFF; // -1 >>> MAP_ID_SIZE in Java

    AddressMapImpl();
    AddressMapImpl(uint8_t mapID, AddressFactory* addrFactory);
    virtual ~AddressMapImpl() override = default;

    // AddressMap overrides
    int getNumAddressSpaces() const override;
    AddressSpace* getLanguageAddressSpace(int id) const override;
    int getLanguageAddressSpaceID(const AddressSpace* space) const override;
    Address mapLanguageAddress(const Address& langAddr) const override;
    Address mapInternalAddress(const Address& internalAddr) const override;
    int getOverlaySpaceCount() const override;
    AddressSpace* getOverlaySpace(const std::string& name) const override;
    AddressSpace* createOverlaySpace(const std::string& name, AddressSpace* baseSpace) override;
    bool removeOverlaySpace(const std::string& name) override;
    std::vector<std::string> getOverlaySpaceNames() const override;
    bool hasOverlaySpaces() const override;
    AddressSpace* getDefaultAddressSpace() const override;

    // Encoding & Decoding APIs (matching Java AddressMapImpl)
    Address decodeAddress(uint64_t value);
    uint64_t getKey(const Address& addr);
    int findKeyRange(const std::vector<KeyRange>& keyRangeList, const Address& addr);
    std::vector<KeyRange> getKeyRanges(const Address& start, const Address& end);
    std::vector<KeyRange> getKeyRanges(const AddressSetView* set);

    void reconcile();

private:
    void init();
    int getBaseAddressIndex(const Address& addr);
    void checkAddressSpace(AddressSpace* addrSpace);

    mutable std::recursive_mutex mutex_;
    uint8_t mapID_ = 0;
    uint64_t mapIdBits_ = 0;
    AddressFactory* addrFactory_ = nullptr;

    std::vector<Address> baseAddrs_;
    std::vector<Address> sortedBaseStartAddrs_;
    std::vector<Address> sortedBaseEndAddrs_;
    std::unordered_map<Address, int> addrToIndexMap_;
    int lastBaseIndex_ = -1;

    std::unordered_map<std::string, AddressSpace*> spaceMap_;
    AddressSpace* stackSpace_ = nullptr;

    // Overlay storage owned by this map
    std::unordered_map<std::string, std::unique_ptr<AddressSpace>> overlaySpaces_;
    int nextUniqueOverlay_ = 1000;
};

} // namespace ghidra
