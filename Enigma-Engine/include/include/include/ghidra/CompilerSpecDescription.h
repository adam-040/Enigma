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

#include <ghidra/CompilerSpecID.h>

namespace ghidra {

class CompilerSpecDescription {
public:
    CompilerSpecDescription() = default;
    CompilerSpecDescription(const CompilerSpecID& id, const std::string& name = "",
                            const std::string& source = "")
        : compilerSpecID_(id), name_(name), source_(source) {}

    virtual ~CompilerSpecDescription() = default;
    virtual const CompilerSpecID& getCompilerSpecID() const { return compilerSpecID_; }
    virtual const std::string& getCompilerSpecName() const { return name_; }
    virtual const std::string& getSource() const { return source_; }

    /// Backward-compatible alias
    const std::string& getId() const { return compilerSpecID_.getIdAsString(); }

private:
    CompilerSpecID compilerSpecID_;
    std::string name_;
    std::string source_;
};

} // namespace ghidra
