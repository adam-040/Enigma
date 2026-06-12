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

#include <string>

namespace ghidra {

class Location {
public:
    Location() = default;
    Location(const std::string& src, int line) : source_(src), line_(line) {}

    const std::string& getSource() const { return source_; }
    int getLine() const { return line_; }

private:
    std::string source_;
    int line_ = 0;
};

} // namespace ghidra
