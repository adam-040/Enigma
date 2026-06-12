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

#include <functional>

namespace ghidra {
namespace graph {

class Vertex {
public:
    explicit Vertex(int key) : key_(key) {}
    int key() const { return key_; }
    bool operator==(const Vertex& other) const { return key_ == other.key_; }
    bool operator!=(const Vertex& other) const { return !(*this == other); }
    struct Hash {
        size_t operator()(const Vertex& v) const {
            return std::hash<int>()(v.key());
        }
    };
private:
    int key_;
};

} // namespace graph
} // namespace ghidra
