/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CustomOrganization.h
/// \brief Custom data organization with name, size, and alignment.
#pragma once

#include <string>

namespace ghidra {

class CustomOrganization {
public:
    CustomOrganization(const std::string& name, int size, int alignment)
        : name_(name), size_(size), alignment_(alignment) {}

    std::string getName() const { return name_; }
    int getSize() const { return size_; }
    int getAlignment() const { return alignment_; }

private:
    std::string name_;
    int size_;
    int alignment_;
};

} // namespace ghidra
