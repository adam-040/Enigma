/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CompilerSpecID.h
/// \brief Represents a compiler specification (gcc, borlandcpp, etc)
#pragma once

#include <string>
#include <functional>

namespace ghidra {

/**
 * Represents an opinion's compiler (gcc, borlandcpp, etc).
 * Translated from: ghidra.program.model.lang.CompilerSpecID
 */
class CompilerSpecID {
public:
    static constexpr const char* DEFAULT_ID = "default";

private:
    std::string id_;

public:
    /// Creates a new compiler spec ID.
    /// \param id The compiler ID (gcc, borlandcpp, etc). Empty defaults to "default".
    explicit CompilerSpecID(const std::string& id = DEFAULT_ID)
        : id_(id.empty() ? DEFAULT_ID : id) {}

    /// Gets the compiler spec ID as a string.
    const std::string& getIdAsString() const { return id_; }

    /// String representation
    const std::string& toString() const { return id_; }

    bool operator==(const CompilerSpecID& other) const { return id_ == other.id_; }
    bool operator!=(const CompilerSpecID& other) const { return id_ != other.id_; }
    bool operator<(const CompilerSpecID& other) const { return id_ < other.id_; }

    std::size_t hash() const {
        return std::hash<std::string>{}(id_);
    }
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::CompilerSpecID> {
        std::size_t operator()(const ghidra::CompilerSpecID& cid) const { return cid.hash(); }
    };
}
