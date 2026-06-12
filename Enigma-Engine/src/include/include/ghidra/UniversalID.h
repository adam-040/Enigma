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
/// \file UniversalID.h
/// \brief Unique identifier wrapper (64-bit value)
/// Translated from: ghidra.util.UniversalID
#pragma once

#include <cstdint>
#include <string>

namespace ghidra {

/**
 * A unique identifier represented as a 64-bit value.
 * Used to uniquely identify data types, categories, and other kernel objects.
 */
class UniversalID {
private:
    int64_t id_;

public:
    /// Construct a UniversalID with the given value
    explicit UniversalID(int64_t id = 0)
        : id_(id) {}

    /// Get the underlying value
    int64_t getValue() const { return id_; }

    bool operator==(const UniversalID& other) const { return id_ == other.id_; }
    bool operator!=(const UniversalID& other) const { return id_ != other.id_; }
    bool operator<(const UniversalID& other) const { return id_ < other.id_; }
    bool operator>(const UniversalID& other) const { return id_ > other.id_; }

    std::string toString() const { return std::to_string(id_); }
};

} // namespace ghidra

namespace std {
    template<>
    struct hash<ghidra::UniversalID> {
        size_t operator()(const ghidra::UniversalID& id) const {
            int64_t v = id.getValue();
            return static_cast<size_t>(v ^ (v >> 32));
        }
    };
}
