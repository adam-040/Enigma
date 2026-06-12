/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SnapshotWriter.h
/// \brief Serializes ProgramDB to FlatBuffers ProgramSnapshot.
#pragma once

#include <ghidra/ProgramDB.h>
#include <string>
#include <vector>

namespace ghidra {
namespace storage {

class SnapshotWriter {
public:
    /// Serialize the given ProgramDB into a FlatBuffers binary buffer.
    /// Returns the serialized bytes.
    static std::vector<uint8_t> serialize(const ProgramDB& program);

    /// Write a buffer to a file path.
    static bool writeFile(const std::string& path, const std::vector<uint8_t>& data);

private:
    static uint64_t addressToU64(const Address& addr);
};

} // namespace storage
} // namespace ghidra
