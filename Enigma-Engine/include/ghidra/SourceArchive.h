/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceArchive.h
/// \brief Tracks a data type archive which supplied data types to a program
/// Translated from: ghidra.program.model.data.SourceArchive
#pragma once

#include <cstdint>
#include <string>
#include "ghidra/ArchiveType.h"
#include "ghidra/UniversalID.h"

namespace ghidra {

/**
 * SourceArchive holds information about a single data type archive which supplied a data type
 * to the program.
 */
class SourceArchive {
public:
    virtual ~SourceArchive() = default;

    virtual UniversalID getSourceArchiveID() const = 0;
    virtual std::string getDomainFileID() const = 0;
    virtual ArchiveType getArchiveType() const = 0;
    virtual std::string getName() const = 0;
    virtual int64_t getLastSyncTime() const = 0;
    virtual bool isDirty() const = 0;

    virtual void setLastSyncTime(int64_t time) = 0;
    virtual void setName(const std::string& name) = 0;
    virtual void setDirtyFlag(bool dirty) = 0;
};

} // namespace ghidra
