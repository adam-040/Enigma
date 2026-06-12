/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/ExternalLocationAdapter.h"

namespace ghidra {

ExternalLocationAdapter::ExternalLocationAdapter(std::vector<ExternalLocation*> locations)
    : locations_(std::move(locations)), index_(0) {}

ExternalLocationAdapter::ExternalLocationAdapter(
    std::vector<ExternalLocation*>::iterator begin,
    std::vector<ExternalLocation*>::iterator end)
    : locations_(begin, end), index_(0) {}

bool ExternalLocationAdapter::hasNext() {
    return index_ < locations_.size();
}

ExternalLocation* ExternalLocationAdapter::next() {
    if (!hasNext()) return nullptr;
    return locations_[index_++];
}

} // namespace ghidra
