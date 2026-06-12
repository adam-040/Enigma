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

#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <memory>
#include <string>

namespace ghidra {

class OverlayAddressSpace : public GenericAddressSpace {
private:
    AddressSpace* baseSpace_;
    std::string orderedKey_;

public:
    static constexpr const char* OV_SEPARATOR = ":";

    OverlayAddressSpace(AddressSpace* baseSpace, int unique, const std::string& orderedKey)
        : GenericAddressSpace(orderedKey, baseSpace->getSize(), baseSpace->getType(), unique),
          baseSpace_(baseSpace), orderedKey_(orderedKey) {}

    virtual ~OverlayAddressSpace() override = default;

    const std::string& getOrderedKey() const {
        return orderedKey_;
    }

    bool isOverlaySpace() const override {
        return true;
    }

    AddressSpace* getOverlayedSpace() const {
        return baseSpace_;
    }

    AddressSpace* getPhysicalSpace() override {
        return baseSpace_->getPhysicalSpace();
    }

    bool hasMappedRegisters() const override {
        return baseSpace_->hasMappedRegisters();
    }

    virtual bool contains(int64_t offset) const = 0;

    virtual AddressSet getOverlayAddressSet() const = 0;

    Address getAddressInThisSpaceOnly(int64_t offset) {
        return Address(this, offset);
    }

    Address getAddress(int64_t offset) {
        if (contains(offset)) {
            return Address(this, offset);
        }
        return Address(baseSpace_, offset);
    }

    Address getOverlayAddress(const Address& addr) {
        if (baseSpace_ == addr.getAddressSpace()) {
            if (contains(addr.getOffset())) {
                return Address(this, addr.getOffset());
            }
        }
        return addr;
    }

    Address translateAddress(const Address& addr, bool forceTranslation = false) {
        if (!addr.isValid()) {
            return Address();
        }
        if (!forceTranslation && contains(addr.getOffset())) {
            return addr;
        }
        return Address(baseSpace_, addr.getOffset());
    }

    int getBaseSpaceID() const {
        return baseSpace_->getSpaceID();
    }

    bool showSpaceName() const override {
        return true;
    }

    int compareOverlay(const OverlayAddressSpace& overlay) const {
        if (this == &overlay) {
            return 0;
        }
        int rc = baseSpace_->getSpaceID() - overlay.baseSpace_->getSpaceID();
        if (rc != 0) {
            return rc;
        }
        int c = getType() - overlay.getType();
        if (c == 0) {
            c = orderedKey_.compare(overlay.orderedKey_);
        }
        return c;
    }
};

} // namespace ghidra
