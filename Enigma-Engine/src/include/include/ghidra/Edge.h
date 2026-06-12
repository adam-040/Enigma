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

#include <ghidra/Vertex.h>
#include <functional>

namespace ghidra {
namespace graph {

class Edge {
public:
    Edge(const Vertex& from, const Vertex& to) : from_(from), to_(to) {}
    const Vertex& from() const { return from_; }
    const Vertex& to() const { return to_; }
    bool operator==(const Edge& other) const {
        return from_ == other.from_ && to_ == other.to_;
    }
    bool operator!=(const Edge& other) const { return !(*this == other); }
    struct Hash {
        size_t operator()(const Edge& e) const {
            size_t h1 = std::hash<int>()(e.from().key());
            size_t h2 = std::hash<int>()(e.to().key());
            return h1 ^ (h2 << 1);
        }
    };
private:
    Vertex from_;
    Vertex to_;
};

} // namespace graph
} // namespace ghidra
