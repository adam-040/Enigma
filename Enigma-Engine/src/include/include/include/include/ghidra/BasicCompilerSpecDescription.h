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

#include <ghidra/CompilerSpecDescription.h>
#include <ghidra/CompilerSpecID.h>

namespace ghidra {

class BasicCompilerSpecDescription : public CompilerSpecDescription {
public:
    BasicCompilerSpecDescription(const CompilerSpecID& id, const std::string& name)
        : id_(id), name_(name) {}

    const CompilerSpecID& getCompilerSpecID() const override { return id_; }
    const std::string& getCompilerSpecName() const override { return name_; }
    const std::string& getSource() const override {
        static std::string source = id_.toString() + " " + name_;
        return source;
    }

    std::string toString() const { return name_; }

    bool operator==(const BasicCompilerSpecDescription& other) const {
        return id_ == other.id_;
    }
    bool operator!=(const BasicCompilerSpecDescription& other) const {
        return !(*this == other);
    }

private:
    CompilerSpecID id_;
    std::string name_;
};

} // namespace ghidra
