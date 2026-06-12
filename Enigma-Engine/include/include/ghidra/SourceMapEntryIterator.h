/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/SourceMapEntry.h>
#include <vector>
#include <cstddef>

namespace ghidra {

class SourceMapEntryIterator {
public:
    SourceMapEntryIterator() = default;
    explicit SourceMapEntryIterator(const std::vector<SourceMapEntry>& entries)
        : entries_(entries), index_(0) {}

    bool hasNext() const {
        return index_ < entries_.size();
    }

    SourceMapEntry next() {
        if (!hasNext()) return SourceMapEntry();
        return entries_[index_++];
    }

private:
    std::vector<SourceMapEntry> entries_;
    size_t index_ = 0;
};

} // namespace ghidra
