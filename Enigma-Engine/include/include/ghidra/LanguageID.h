/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file LanguageID.h
/// \brief Represents a processor language (x86:LE:32:default, 8051:BE:16:default, etc)
#pragma once

#include <string>
#include <stdexcept>
#include <functional>

namespace ghidra {

/**
 * Represents an opinion's processor language (x86:LE:32:default, etc).
 * Translated from: ghidra.program.model.lang.LanguageID
 */
class LanguageID {
private:
    std::string id_;

public:
    LanguageID() = default;

    /// Creates a new language ID.
    /// \param id The language ID (x86:LE:32:default, 8051:BE:16:default, etc).
    /// \throws std::invalid_argument if the language ID is null or empty.
    explicit LanguageID(const std::string& id) : id_(id) {
        if (id.empty()) {
            throw std::invalid_argument("empty id not allowed");
        }
    }

    /// Gets the language ID as a string.
    const std::string& getIdAsString() const { return id_; }

    /// String representation
    const std::string& toString() const { return id_; }

    bool operator==(const LanguageID& other) const { return id_ == other.id_; }
    bool operator!=(const LanguageID& other) const { return id_ != other.id_; }
    bool operator<(const LanguageID& other) const { return id_ < other.id_; }

    std::size_t hash() const {
        return std::hash<std::string>{}(id_);
    }
};

} // namespace ghidra

namespace std {
    template<> struct hash<ghidra::LanguageID> {
        std::size_t operator()(const ghidra::LanguageID& lid) const { return lid.hash(); }
    };
}
