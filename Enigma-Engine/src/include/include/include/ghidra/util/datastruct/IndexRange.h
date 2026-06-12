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
/// \file IndexRange.h
/// \brief Class for holding a begin and end index
/// Translated from: ghidra.util.datastruct.IndexRange
#pragma once

#include <cstdint>
#include <functional>

namespace ghidra {

/// \brief Simple range with start and end indices.
class IndexRange {
public:
    IndexRange() : start_(0), end_(0) {}
    IndexRange(int64_t start, int64_t end) : start_(start), end_(end) {}

    int64_t getStart() const { return start_; }
    int64_t getEnd() const { return end_; }

    bool operator==(const IndexRange& other) const {
        return start_ == other.start_ && end_ == other.end_;
    }

    bool operator!=(const IndexRange& other) const {
        return !(*this == other);
    }

    bool operator<(const IndexRange& other) const {
        if (start_ != other.start_) return start_ < other.start_;
        return end_ < other.end_;
    }

private:
    int64_t start_;
    int64_t end_;
};

} // namespace ghidra

namespace std {
template<>
struct hash<ghidra::IndexRange> {
    size_t operator()(const ghidra::IndexRange& r) const {
        return static_cast<size_t>(r.getStart() ^ (r.getStart() >> 32));
    }
};
} // namespace std
