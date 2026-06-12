/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RelocationUtil.cpp
/// \brief Utility for finding relocation handlers.
#include "ghidra/RelocationUtil.h"
#include <mutex>

namespace ghidra {

namespace {
std::vector<RelocationHandler*>& registry() {
    static std::vector<RelocationHandler*> r;
    return r;
}
std::mutex& registryMutex() {
    static std::mutex m;
    return m;
}
}

std::vector<RelocationHandler*> RelocationUtil::getRelocationHandlers() {
    std::lock_guard<std::mutex> lock(registryMutex());
    return registry();
}

void RelocationUtil::registerHandler(RelocationHandler* handler) {
    if (handler == nullptr) return;
    std::lock_guard<std::mutex> lock(registryMutex());
    auto& r = registry();
    for (auto* h : r) {
        if (h == handler) return;
    }
    r.push_back(handler);
}

} // namespace ghidra
