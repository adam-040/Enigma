/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrimitiveExtractor.h
/// \brief Class for extracting primitive elements of a data-type
/// Translated from: ghidra.program.model.lang.protorules.PrimitiveExtractor
#pragma once

#include <ghidra/DataType.h>
#include <ghidra/Metatype.h>
#include <vector>

namespace ghidra {

class PrimitiveExtractor {
public:
    struct Primitive {
        DataType* dt;
        int offset;
        Primitive(DataType* d, int off) : dt(d), offset(off) {}
    };

    PrimitiveExtractor(DataType* dt, bool unionIllegal, int offset, int max);
    int size() const { return static_cast<int>(primitives.size()); }
    const Primitive& get(int i) const { return primitives[i]; }
    bool isValid() const { return valid_; }
    bool containsUnknown() const { return (flags_ & FLAG_UNKNOWN) != 0; }
    bool isAligned() const { return (flags_ & FLAG_UNALIGNED) == 0; }
    bool containsHoles() const { return (flags_ & FLAG_EXTRA_SPACE) != 0; }

private:
    static const int FLAG_UNKNOWN = 1;
    static const int FLAG_UNALIGNED = 2;
    static const int FLAG_EXTRA_SPACE = 4;
    static const int FLAG_INVALID = 8;
    static const int FLAG_UNION_INVALID = 16;

    std::vector<Primitive> primitives;
    int flags_ = 0;
    bool valid_ = true;

    int checkOverlap(std::vector<Primitive>& res, std::vector<Primitive>& small,
                     int point, Primitive& big);
    bool commonRefinement(std::vector<Primitive>& first, std::vector<Primitive>& second);
    bool handleUnion(class Union* dt, int max, int offset);
    bool extract(DataType* dt, int max, int offset);
};

} // namespace ghidra
