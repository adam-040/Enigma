/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SnapshotReader.h
/// \brief Deserializes FlatBuffers ProgramSnapshot back to ProgramDB.
#pragma once

#include <ghidra/ProgramDB.h>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {
namespace storage {

class SnapshotReader {
public:
    /// Read a file into a byte buffer.
    static std::vector<uint8_t> readFile(const std::string& path);

    /// Validate that the schema version is supported.
    /// Throws std::runtime_error if not.
    static void validateSchemaVersion(const uint8_t* data, size_t size);

    /// Deserialize a ProgramSnapshot buffer into a ProgramDB.
    /// Returns a fully populated ProgramDB.
    static std::unique_ptr<ProgramDB> deserialize(const uint8_t* data, size_t size);

    /// Convenience: read file + validate + deserialize.
    static std::unique_ptr<ProgramDB> loadFromFile(const std::string& path);
};

} // namespace storage
} // namespace ghidra
