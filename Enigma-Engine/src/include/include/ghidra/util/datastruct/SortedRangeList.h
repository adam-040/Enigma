/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/// \file SortedRangeList.h
/// \brief A sorted collection of non-overlapping integer ranges
/// Translated from: ghidra.util.datastruct.SortedRangeList
#pragma once

#include <cstdint>
#include <set>
#include <vector>
#include <string>
#include <functional>

namespace ghidra {

/// \brief A sorted list of non-overlapping, non-adjacent integer ranges.
///
/// Ranges are stored as [min, max] pairs in a sorted set. Adjacent and
/// overlapping ranges are automatically merged on insertion. This is the
/// integer-domain analog of AddressSet.
class SortedRangeList {
public:
    /// A single inclusive integer range [min, max]
    struct Range {
        int64_t min;
        int64_t max;

        Range() : min(0), max(0) {}
        Range(int64_t mn, int64_t mx) : min(mn), max(mx) {}

        bool contains(int64_t val) const { return val >= min && val <= max; }
        int64_t size() const { return max - min + 1; }

        bool operator<(const Range& other) const { return min < other.min; }
        bool operator==(const Range& other) const { return min == other.min && max == other.max; }
        bool operator!=(const Range& other) const { return !(*this == other); }
    };

    using iterator = std::set<Range>::const_iterator;

private:
    std::set<Range> ranges_;
    int64_t numValues_;

public:
    SortedRangeList();
    SortedRangeList(const SortedRangeList& other);
    SortedRangeList& operator=(const SortedRangeList& other);
    ~SortedRangeList() = default;

    /// Add a single value
    void addRange(int64_t value);

    /// Add an inclusive range [min, max]
    void addRange(int64_t min, int64_t max);

    /// Remove a single value
    void removeRange(int64_t value);

    /// Remove an inclusive range [min, max]
    void removeRange(int64_t min, int64_t max);

    /// Check if a value is contained in any range
    bool contains(int64_t value) const;

    /// Check if the entire range [min, max] is contained
    bool contains(int64_t min, int64_t max) const;

    /// Get the number of individual values covered by all ranges
    int64_t getNumValues() const { return numValues_; }

    /// Get the number of disjoint ranges
    int getNumRanges() const { return static_cast<int>(ranges_.size()); }

    /// Check if the range list is empty
    bool isEmpty() const { return ranges_.empty(); }

    /// Clear all ranges
    void clear();

    /// Get the minimum value across all ranges, or 0 if empty
    int64_t getMin() const;

    /// Get the maximum value across all ranges, or 0 if empty
    int64_t getMax() const;

    /// Get the range containing the given value, or nullptr if not found
    const Range* getRangeContaining(int64_t value) const;

    /// Get all ranges as a vector
    std::vector<Range> getRanges() const;

    /// Iterate over all ranges
    iterator begin() const { return ranges_.begin(); }
    iterator end() const { return ranges_.end(); }

    /// String representation
    std::string toString() const;

    bool operator==(const SortedRangeList& other) const;
    bool operator!=(const SortedRangeList& other) const { return !(*this == other); }
};

} // namespace ghidra
