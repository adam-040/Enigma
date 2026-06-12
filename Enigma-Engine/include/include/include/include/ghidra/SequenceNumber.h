#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <compare>
#include <string>
#include <sstream>
#include <iomanip>

namespace ghidra {

class SequenceNumber {
public:
    SequenceNumber(Address instrAddr, int sequenceNum) 
        : pc(instrAddr), uniq(sequenceNum), order(0) {}

    Address getTarget() const {
        return pc;
    }

    int getTime() const {
        return uniq;
    }

    void setTime(int t) {
        uniq = t;
    }

    int getOrder() const {
        return order;
    }

    void setOrder(int o) {
        order = o;
    }

    bool operator==(const SequenceNumber& other) const {
        return pc == other.pc && uniq == other.uniq;
    }

    bool operator!=(const SequenceNumber& other) const {
        return !(*this == other);
    }

    bool operator<(const SequenceNumber& other) const {
        if (pc < other.pc) return true;
        if (other.pc < pc) return false;
        return uniq < other.uniq;
    }

    bool operator>(const SequenceNumber& other) const {
        return other < *this;
    }

    bool operator<=(const SequenceNumber& other) const {
        return ! (other < *this);
    }

    bool operator>=(const SequenceNumber& other) const {
        return ! (*this < other);
    }

    std::string toString() const {
        std::stringstream ss;
        ss << "(" << pc.getAddressSpace()->getName() << ", 0x" 
           << std::hex << pc.getOffset() << ", " 
           << std::dec << uniq << ", " << order << ")";
        return ss.str();
    }

    size_t hash() const {
        return std::hash<std::string>{}(pc.toString()) ^ (std::hash<int>{}(uniq) << 1);
    }

private:
    Address pc;
    int uniq = 0;
    int order = 0;
};

} // namespace ghidra
