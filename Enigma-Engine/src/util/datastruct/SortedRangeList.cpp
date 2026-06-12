/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file SortedRangeList.cpp
/// \brief Implementation of the sorted integer range list

#include <ghidra/util/datastruct/SortedRangeList.h>
#include <sstream>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

SortedRangeList::SortedRangeList() : numValues_(0) {}

SortedRangeList::SortedRangeList(const SortedRangeList& other)
    : ranges_(other.ranges_), numValues_(other.numValues_) {}

SortedRangeList& SortedRangeList::operator=(const SortedRangeList& other) {
    if (this != &other) {
        ranges_ = other.ranges_;
        numValues_ = other.numValues_;
    }
    return *this;
}

void SortedRangeList::addRange(int64_t value) {
    addRange(value, value);
}

void SortedRangeList::addRange(int64_t min, int64_t max) {
    if (min > max) {
        throw std::invalid_argument("SortedRangeList::addRange: min > max");
    }

    // Find all existing ranges that overlap or are adjacent to [min, max]
    // A range [a, b] overlaps/is adjacent if a <= max+1 and b >= min-1
    int64_t newMin = min;
    int64_t newMax = max;

    // Use a search range to find candidates
    auto it = ranges_.begin();
    while (it != ranges_.end()) {
        // If this range is completely after the new range (with gap > 1), stop
        if (it->min > newMax + 1) break;

        // If this range is completely before the new range (with gap > 1), skip
        if (it->max < newMin - 1) {
            ++it;
            continue;
        }

        // Overlap or adjacent - merge
        newMin = std::min(newMin, it->min);
        newMax = std::max(newMax, it->max);
        numValues_ -= it->size();
        it = ranges_.erase(it);
    }

    Range merged(newMin, newMax);
    ranges_.insert(merged);
    numValues_ += merged.size();
}

void SortedRangeList::removeRange(int64_t value) {
    removeRange(value, value);
}

void SortedRangeList::removeRange(int64_t min, int64_t max) {
    if (min > max) {
        throw std::invalid_argument("SortedRangeList::removeRange: min > max");
    }

    auto it = ranges_.begin();
    std::vector<Range> toAdd;

    while (it != ranges_.end()) {
        if (it->min > max) break;

        if (it->max < min) {
            ++it;
            continue;
        }

        int64_t rMin = it->min;
        int64_t rMax = it->max;
        numValues_ -= it->size();
        it = ranges_.erase(it);

        // Keep the part before [min, max]
        if (rMin < min) {
            Range before(rMin, min - 1);
            toAdd.push_back(before);
            numValues_ += before.size();
        }

        // Keep the part after [min, max]
        if (rMax > max) {
            Range after(max + 1, rMax);
            toAdd.push_back(after);
            numValues_ += after.size();
        }
    }

    for (const auto& r : toAdd) {
        ranges_.insert(r);
    }
}

bool SortedRangeList::contains(int64_t value) const {
    // Find the range with min <= value (upper_bound then decrement)
    Range search(value, value);
    auto it = ranges_.upper_bound(search);
    if (it != ranges_.begin()) {
        --it;
        return it->contains(value);
    }
    return false;
}

bool SortedRangeList::contains(int64_t min, int64_t max) const {
    Range search(min, min);
    auto it = ranges_.upper_bound(search);
    if (it != ranges_.begin()) {
        --it;
        return it->min <= min && it->max >= max;
    }
    return false;
}

void SortedRangeList::clear() {
    ranges_.clear();
    numValues_ = 0;
}

int64_t SortedRangeList::getMin() const {
    if (ranges_.empty()) return 0;
    return ranges_.begin()->min;
}

int64_t SortedRangeList::getMax() const {
    if (ranges_.empty()) return 0;
    return ranges_.rbegin()->max;
}

const SortedRangeList::Range* SortedRangeList::getRangeContaining(int64_t value) const {
    Range search(value, value);
    auto it = ranges_.upper_bound(search);
    if (it != ranges_.begin()) {
        --it;
        if (it->contains(value)) {
            return &(*it);
        }
    }
    return nullptr;
}

std::vector<SortedRangeList::Range> SortedRangeList::getRanges() const {
    return std::vector<Range>(ranges_.begin(), ranges_.end());
}

std::string SortedRangeList::toString() const {
    std::stringstream ss;
    ss << "[";
    bool first = true;
    for (const auto& r : ranges_) {
        if (!first) ss << ", ";
        ss << "[" << r.min << "," << r.max << "]";
        first = false;
    }
    ss << "]";
    return ss.str();
}

bool SortedRangeList::operator==(const SortedRangeList& other) const {
    return ranges_ == other.ranges_;
}

} // namespace ghidra
