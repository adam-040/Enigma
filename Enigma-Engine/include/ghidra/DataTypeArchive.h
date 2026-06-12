/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeArchive.h
/// \brief Main entry point into an object which stores all information relating to a data type archive
/// Translated from: ghidra.program.model.listing.DataTypeArchive
#pragma once

#include <cstdint>
#include <string>

namespace ghidra {

class DataTypeManager;
class DataTypeArchiveChangeSet;

/**
 * This interface represents the main entry point into an object which
 * stores all information relating to a single data type archive.
 */
class DataTypeArchive {
public:
    static inline const std::string DATA_TYPE_ARCHIVE_INFO = "Data Type Archive Information";
    static inline const std::string DATA_TYPE_ARCHIVE_SETTINGS = "Data Type Archive Settings";
    static inline const std::string DATE_CREATED = "Date Created";
    static inline const std::string CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";

    virtual ~DataTypeArchive() = default;

    virtual DataTypeManager* getDataTypeManager() = 0;
    virtual int getDefaultPointerSize() const = 0;
    virtual int64_t getCreationDate() const = 0;
    virtual DataTypeArchiveChangeSet* getChanges() = 0;
    virtual void invalidate() = 0;
};

} // namespace ghidra
