/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file TaskMonitor.cpp
/// \brief Implementation of TaskMonitor default methods
#include "ghidra/TaskMonitor.h"

namespace ghidra {

void TaskMonitor::initialize(int64_t max, const std::string& message) {
    initialize(max);
    setMessage(message);
}

void TaskMonitor::checkCancelled() {
    if (isCancelled()) {
        throw CancelledException();
    }
}

void TaskMonitor::incrementProgress() {
    incrementProgress(1);
}

void TaskMonitor::increment() {
    checkCancelled();
    incrementProgress(1);
}

void TaskMonitor::increment(int64_t incrementAmount) {
    checkCancelled();
    incrementProgress(incrementAmount);
}

} // namespace ghidra
