#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <algorithm>
#include "ghidra/Address.h"

namespace ghidra {

class AddressRange {
protected:
    Address minAddr_;
    Address maxAddr_;

public:
    AddressRange() = default;
    AddressRange(const Address& minAddr, const Address& maxAddr) : minAddr_(minAddr), maxAddr_(maxAddr) {}
    virtual ~AddressRange() = default;

    virtual int64_t getLength() const {
        if (!minAddr_.getAddressSpace() || !maxAddr_.getAddressSpace()) return 0;
        return maxAddr_.subtract(minAddr_) + 1;
    }

    virtual uint64_t getBigLength() const {
        if (!minAddr_.getAddressSpace() || !maxAddr_.getAddressSpace()) return 0;
        return static_cast<uint64_t>(maxAddr_.subtract(minAddr_)) + 1;
    }

    virtual bool contains(const Address& addr) const {
        return addr >= minAddr_ && addr <= maxAddr_;
    }

    virtual bool intersects(const AddressRange& range) const {
        return !(maxAddr_ < range.minAddr_ || range.maxAddr_ < minAddr_);
    }

    virtual bool intersects(const Address& start, const Address& end) const {
        return !(maxAddr_ < start || end < minAddr_);
    }

    virtual AddressRange* intersect(const AddressRange& range) const {
        Address iMin = (minAddr_ > range.minAddr_) ? minAddr_ : range.minAddr_;
        Address iMax = (maxAddr_ < range.maxAddr_) ? maxAddr_ : range.maxAddr_;
        if (iMin > iMax) return nullptr;
        return new AddressRange(iMin, iMax);
    }

    virtual AddressRange* intersectRange(const Address& start, const Address& end) const {
        Address iMin = (minAddr_ > start) ? minAddr_ : start;
        Address iMax = (maxAddr_ < end) ? maxAddr_ : end;
        if (iMin > iMax) return nullptr;
        return new AddressRange(iMin, iMax);
    }

    virtual int compareTo(const Address& addr) const {
        if (addr < minAddr_) return 1;
        if (addr > maxAddr_) return -1;
        return 0;
    }

    virtual int compareTo(const AddressRange& other) const {
        if (minAddr_ < other.minAddr_) return -1;
        if (other.minAddr_ < minAddr_) return 1;
        if (maxAddr_ < other.maxAddr_) return -1;
        if (other.maxAddr_ < maxAddr_) return 1;
        return 0;
    }

    virtual const Address& getMaxAddress() const { return maxAddr_; }
    virtual const Address& getMinAddress() const { return minAddr_; }
    virtual AddressSpace* getAddressSpace() const { return minAddr_.getAddressSpace(); }

    virtual bool equals(const AddressRange& other) const {
        return minAddr_ == other.minAddr_ && maxAddr_ == other.maxAddr_;
    }

    virtual bool operator==(const AddressRange& other) const { return equals(other); }
    bool operator!=(const AddressRange& other) const { return !equals(other); }
    virtual bool operator<(const AddressRange& other) const { return compareTo(other) < 0; }
    bool operator>(const AddressRange& other) const { return compareTo(other) > 0; }

    virtual std::string toString() const {
        return minAddr_.toString() + "->" + maxAddr_.toString();
    }

    static void checkValidRange(const Address& start, const Address& end) {
        if (!start.hasSameAddressSpace(end)) {
            throw std::invalid_argument(
                "Start and end addresses must be in same address space!  Start " +
                start.toString() + "   end = " + end.toString());
        }
        if (start > end) {
            throw std::invalid_argument(
                "Start address must be less than or equal to end address:  Start " +
                start.toString() + "   end = " + end.toString());
        }
    }
};

} // namespace ghidra
