#pragma once

#include <ghidra/Address.h>
#include <string>
#include <optional>

namespace ghidra {

class AddressLabelInfo {
public:
    AddressLabelInfo() = default;
    AddressLabelInfo(const Address& addr, int sizeInBytes, const std::string& label,
                     const std::string& description, bool isPrimary, bool isEntry)
        : addr_(addr), endAddr_(addr.add(sizeInBytes - 1)), label_(label),
          description_(description), isPrimary_(isPrimary), isEntry_(isEntry),
          sizeInBytes_(sizeInBytes) {}

    const Address& getAddress() const { return addr_; }
    const Address& getEndAddress() const { return endAddr_; }
    const std::string& getLabel() const { return label_; }
    const std::string& getDescription() const { return description_; }
    int getByteSize() const { return sizeInBytes_; }
    bool isPrimary() const { return isPrimary_; }
    bool isEntry() const { return isEntry_; }
    bool isVolatile() const { return isVolatile_.value_or(false); }
    void setVolatile(bool v) { isVolatile_ = v; }

    int compareTo(const AddressLabelInfo& other) const {
        if (addr_ < other.addr_) return -1;
        if (other.addr_ < addr_) return 1;
        return label_.compare(other.label_);
    }
    bool operator==(const AddressLabelInfo& other) const { return compareTo(other) == 0; }
    bool operator!=(const AddressLabelInfo& other) const { return compareTo(other) != 0; }
    bool operator<(const AddressLabelInfo& other) const { return compareTo(other) < 0; }
    bool operator>(const AddressLabelInfo& other) const { return compareTo(other) > 0; }

private:
    Address addr_;
    Address endAddr_;
    std::string label_;
    std::string description_;
    bool isPrimary_ = false;
    bool isEntry_ = false;
    int sizeInBytes_ = 1;
    std::optional<bool> isVolatile_;
};

} // namespace ghidra
