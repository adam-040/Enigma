/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file WorkingSnapshot.h
/// \brief Atomic save/load of the working snapshot.
#pragma once

#include <ghidra/ProgramDB.h>
#include <memory>
#include <string>

namespace ghidra {
namespace storage {

class WorkingSnapshot {
public:
    /// Save ProgramDB to working.fbs atomically.
    /// Writes to .tmp, fsyncs, then renames to final path.
    static bool save(const ProgramDB& program, const std::string& snapshotPath);

    /// Load ProgramDB from working.fbs.
    static std::unique_ptr<ProgramDB> load(const std::string& snapshotPath);
};

} // namespace storage
} // namespace ghidra
