/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceFile.h
/// \brief Immutable source-file descriptor.
#pragma once

#include "ghidra/SourceFileIdType.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

/**
 * Immutable object representing a source file.
 * Translated from: ghidra.program.database.sourcemap.SourceFile
 */
class SourceFile {
public:
    explicit SourceFile(const std::string& path);
    SourceFile(const std::string& path, SourceFileIdType type, const std::vector<uint8_t>& identifier);
    SourceFile(const std::string& path, SourceFileIdType type,
               const std::vector<uint8_t>& identifier, bool validate);

    const std::string& getPath() const { return path_; }
    const std::string& getFilename() const { return filename_; }
    SourceFileIdType getIdType() const { return idType_; }
    std::vector<uint8_t> getIdentifier() const;
    std::string getIdAsString() const;

    int compareTo(const SourceFile& other) const;
    bool equals(const SourceFile& other) const;
    int hashCode() const { return hash_; }
    std::string toString() const;

private:
    void validatePath();
    void computeDerived();
    std::vector<uint8_t> validateAndCopyIdentifier(const std::vector<uint8_t>& array);
    std::string computeIdDisplayString() const;

    std::string path_;
    std::string filename_;
    SourceFileIdType idType_;
    std::vector<uint8_t> identifier_;
    int hash_;
    std::string idDisplayString_;
};

} // namespace ghidra
