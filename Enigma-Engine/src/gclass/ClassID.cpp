/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ClassID.cpp
/// \brief Class ID implementation
#include <ghidra/ClassID.h>

namespace ghidra {

std::string ClassID::toString() const {
    return categoryPath_.getPath() + " --- " + symbolPath_.getPath();
}

int ClassID::compareTo(const ClassID& other) const {
    if (symbolPath_ < other.symbolPath_) return -1;
    if (other.symbolPath_ < symbolPath_) return 1;
    if (categoryPath_ < other.categoryPath_) return -1;
    if (other.categoryPath_ < categoryPath_) return 1;
    return 0;
}

int ClassID::hashCode() const {
    int prime = 31;
    int result = 1;
    result = prime * result + categoryPath_.hash();
    result = prime * result + symbolPath_.hashCode();
    return result;
}

bool ClassID::operator==(const ClassID& other) const {
    return categoryPath_ == other.categoryPath_ && symbolPath_ == other.symbolPath_;
}

} // namespace ghidra
