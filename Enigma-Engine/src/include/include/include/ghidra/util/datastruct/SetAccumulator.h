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
/// \file SetAccumulator.h
/// \brief Accumulator backed by a set
/// Translated from: ghidra.util.datastruct.SetAccumulator
#pragma once

#include "Accumulator.h"
#include <set>
#include <mutex>

namespace ghidra {

/// \brief An accumulator backed by a mutex-protected set.
///
/// Thread-safe: all mutations are synchronized so data is visible
/// to the client thread. Duplicate items are automatically filtered.
template<typename T>
class SetAccumulator : public Accumulator<T> {
public:
    void add(const T& t) override {
        std::lock_guard<std::mutex> lock(mutex_);
        set_.insert(t);
    }

    void addAll(const std::vector<T>& collection) override {
        std::lock_guard<std::mutex> lock(mutex_);
        set_.insert(collection.begin(), collection.end());
    }

    int32_t getProgress() const override {
        std::lock_guard<std::mutex> lock(mutex_);
        return static_cast<int32_t>(set_.size());
    }

    /// \brief Returns true if the accumulator contains the given item.
    bool contains(const T& t) const {
        std::lock_guard<std::mutex> lock(mutex_);
        return set_.find(t) != set_.end();
    }

    /// \brief Returns a copy of the accumulated set.
    std::set<T> get() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return set_;
    }

    /// \brief Returns the number of items.
    int32_t size() const {
        return getProgress();
    }

private:
    mutable std::mutex mutex_;
    std::set<T> set_;
};

} // namespace ghidra
