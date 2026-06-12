#include <ghidra/Cover.h>
#include <algorithm>
#include <stdexcept>

namespace ghidra {

void Cover::addRange(const Address& start, const Address& end) {
    if (start > end) return;

    AddressRange newRange(start, end);
    std::vector<AddressRange> merged;
    bool inserted = false;

    for (const auto& r : ranges) {
        if (r.intersects(newRange) || r.getMinAddress() == newRange.getMaxAddress().add(1) || newRange.getMinAddress() == r.getMaxAddress().add(1)) {
            Address minAddr = (r.getMinAddress() < newRange.getMinAddress()) ? r.getMinAddress() : newRange.getMinAddress();
            Address maxAddr = (r.getMaxAddress() < newRange.getMaxAddress()) ? newRange.getMaxAddress() : r.getMaxAddress();
            newRange = AddressRange(minAddr, maxAddr);
            inserted = true;
        } else {
            merged.push_back(r);
        }
    }

    if (!inserted) {
        merged.push_back(newRange);
    } else {
        merged.push_back(newRange);
    }

    std::sort(merged.begin(), merged.end());
    ranges = merged;
}

void Cover::removeRange(const Address& start, const Address& end) {
    if (start > end) return;

    std::vector<AddressRange> result;
    for (const auto& r : ranges) {
        if (r.getMinAddress() > end || r.getMaxAddress() < start) {
            result.push_back(r);
        } else {
            if (r.getMinAddress() < start) {
                result.push_back(AddressRange(r.getMinAddress(), start.add(-1)));
            }
            if (r.getMaxAddress() > end) {
                result.push_back(AddressRange(end.add(1), r.getMaxAddress()));
            }
        }
    }
    ranges = result;
}

bool Cover::contains(const Address& addr) const {
    for (const auto& r : ranges) {
        if (r.contains(addr)) return true;
    }
    return false;
}

bool Cover::intersects(const Address& start, const Address& end) const {
    for (const auto& r : ranges) {
        if (r.getMinAddress() <= end && r.getMaxAddress() >= start) return true;
    }
    return false;
}

bool Cover::intersects(const Cover& other) const {
    for (const auto& r1 : ranges) {
        for (const auto& r2 : other.ranges) {
            if (r1.intersects(r2)) return true;
        }
    }
    return false;
}

Cover Cover::intersect(const Cover& other) const {
    Cover result;
    for (const auto& r1 : ranges) {
        for (const auto& r2 : other.ranges) {
            if (r1.intersects(r2)) {
                Address start = (r1.getMinAddress() > r2.getMinAddress()) ? r1.getMinAddress() : r2.getMinAddress();
                Address end = (r1.getMaxAddress() < r2.getMaxAddress()) ? r1.getMaxAddress() : r2.getMaxAddress();
                result.addRange(start, end);
            }
        }
    }
    return result;
}

Cover Cover::subtract(const Cover& other) const {
    Cover result = *this;
    for (const auto& r : other.ranges) {
        result.removeRange(r.getMinAddress(), r.getMaxAddress());
    }
    return result;
}

Cover Cover::merge(const Cover& other) const {
    Cover result = *this;
    for (const auto& r : other.ranges) {
        result.addRange(r.getMinAddress(), r.getMaxAddress());
    }
    return result;
}

bool Cover::operator==(const Cover& other) const {
    if (ranges.size() != other.ranges.size()) return false;
    for (size_t i = 0; i < ranges.size(); i++) {
        if (!(ranges[i] == other.ranges[i])) return false;
    }
    return true;
}

Address Cover::getMinAddress() const {
    if (ranges.empty()) return Address::NO_ADDRESS;
    return ranges.front().getMinAddress();
}

Address Cover::getMaxAddress() const {
    if (ranges.empty()) return Address::NO_ADDRESS;
    return ranges.back().getMaxAddress();
}

uintb Cover::size() const {
    uintb total = 0;
    for (const auto& r : ranges) {
        total += static_cast<uintb>(r.getLength());
    }
    return total;
}

} // namespace ghidra
