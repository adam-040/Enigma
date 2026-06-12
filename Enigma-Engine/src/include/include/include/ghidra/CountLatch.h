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
/// \file CountLatch.h
/// \brief Latch with count that can be incremented/decremented; await blocks until count is 0
/// Translated from: ghidra.util.CountLatch
#pragma once

#include <condition_variable>
#include <mutex>
#include <chrono>

namespace ghidra {

/// \brief A latch with a count that can be incremented and decremented.
///
/// Threads that call await() will block until the count reaches zero.
class CountLatch {
public:
    CountLatch() : count_(0) {}

    /// \brief Increments the latch count.
    void increment() {
        std::lock_guard<std::mutex> lock(mutex_);
        ++count_;
    }

    /// \brief Decrements the latch count and notifies waiters when count reaches zero.
    void decrement() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (count_ > 0) {
            --count_;
            if (count_ == 0) {
                cv_.notify_all();
            }
        }
    }

    /// \brief Returns the current count.
    int getCount() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return count_;
    }

    /// \brief Blocks until the count reaches zero.
    void await() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this]() { return count_ == 0; });
    }

    /// \brief Blocks until count reaches zero or timeout elapses.
    /// \return true if count reached zero, false if timeout elapsed.
    template<typename Rep, typename Period>
    bool await(const std::chrono::duration<Rep, Period>& timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        return cv_.wait_for(lock, timeout, [this]() { return count_ == 0; });
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    int count_;
};

} // namespace ghidra
