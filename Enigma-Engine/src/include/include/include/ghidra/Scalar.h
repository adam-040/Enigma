#pragma once

#include <ghidra/Types.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <limits>

namespace ghidra {

class Scalar {
public:
    Scalar() = default;
    Scalar(int bitLength, int64_t value, bool isSigned = false, bool isHex = false)
        : bitLength_(bitLength), rawValue_(static_cast<uintb>(static_cast<uint64_t>(value))), isSigned_(isSigned), isHex_(isHex) {}

    int getBitLength() const { return bitLength_; }
    int64_t getSignedValue() const {
        if (bitLength_ <= 0) return static_cast<int64_t>(rawValue_);
        uintb mask = (uintb(1) << bitLength_) - 1;
        uintb masked = rawValue_ & mask;
        if (masked >> (bitLength_ - 1)) {
            return static_cast<int64_t>(masked | (~mask));
        }
        return static_cast<int64_t>(masked);
    }
    uintb getUnsignedValue() const {
        if (bitLength_ <= 0) return rawValue_;
        uintb mask = (uintb(1) << bitLength_) - 1;
        return rawValue_ & mask;
    }

    bool isSigned() const { return isSigned_; }
    void setSigned(bool s) { isSigned_ = s; }

    bool isHex() const { return isHex_; }
    void setHex(bool h) { isHex_ = h; }

    std::string toString() const {
        std::stringstream ss;
        if (isHex_) {
            ss << "0x" << std::hex << getUnsignedValue();
        } else {
            ss << std::dec << getSignedValue();
        }
        return ss.str();
    }

    bool operator==(const Scalar& other) const {
        return bitLength_ == other.bitLength_ && rawValue_ == other.rawValue_;
    }
    bool operator!=(const Scalar& other) const { return !(*this == other); }

private:
    int bitLength_ = 0;
    uintb rawValue_ = 0;
    bool isSigned_ = false;
    bool isHex_ = false;
};

} // namespace ghidra
