#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressRange.h>
#include <ghidra/Types.h>
#include <vector>

namespace ghidra {

class Cover {
private:
    std::vector<AddressRange> ranges;

public:
    Cover() = default;
    ~Cover() = default;

    void clear() { ranges.clear(); }
    bool isEmpty() const { return ranges.empty(); }
    int4 getNumRanges() const { return static_cast<int4>(ranges.size()); }
    const AddressRange& getRange(int4 i) const { return ranges.at(i); }

    void addRange(const Address& start, const Address& end);
    void removeRange(const Address& start, const Address& end);
    bool contains(const Address& addr) const;
    bool intersects(const Address& start, const Address& end) const;
    bool intersects(const Cover& other) const;

    Cover intersect(const Cover& other) const;
    Cover subtract(const Cover& other) const;
    Cover merge(const Cover& other) const;

    bool operator==(const Cover& other) const;
    bool operator!=(const Cover& other) const { return !(*this == other); }

    Address getMinAddress() const;
    Address getMaxAddress() const;
    uintb size() const;
};

} // namespace ghidra
