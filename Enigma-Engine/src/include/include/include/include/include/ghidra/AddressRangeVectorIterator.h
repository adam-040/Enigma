#pragma once

#include <ghidra/AddressRangeIterator.h>
#include <vector>

namespace ghidra {

class AddressRangeVectorIterator : public AddressRangeIterator {
private:
    std::vector<AddressRange> ranges_;
    size_t current_;
    bool forward_;

public:
    AddressRangeVectorIterator(const std::vector<AddressRange>& ranges, const Address& start, bool forward)
        : ranges_(ranges), forward_(forward), current_(0) {
        if (forward_) {
            current_ = 0;
            while (current_ < ranges_.size() && ranges_[current_].getMaxAddress() < start) {
                current_++;
            }
        } else {
            current_ = ranges_.size();
            while (current_ > 0 && ranges_[current_ - 1].getMinAddress() > start) {
                current_--;
            }
        }
    }

    bool hasNext() const override {
        if (forward_) return current_ < ranges_.size();
        return current_ > 0;
    }

    const AddressRange& next() override {
        if (!hasNext()) throw std::out_of_range("No more ranges");
        if (forward_) {
            return ranges_[current_++];
        } else {
            return ranges_[--current_];
        }
    }
};

} // namespace ghidra
