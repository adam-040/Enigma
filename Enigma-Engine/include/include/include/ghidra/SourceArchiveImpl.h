/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceArchiveImpl.h
/// \brief In-memory implementation of SourceArchive for use by DataTypeManager
/// Translated from: ghidra.program.model.data.SourceArchiveImpl
#pragma once

#include "ghidra/SourceArchive.h"
#include "ghidra/ArchiveType.h"
#include "ghidra/UniversalID.h"
#include <string>
#include <cstdint>

namespace ghidra {

/**
 * In-memory implementation of SourceArchive.
 * Translated from: ghidra.program.model.data.SourceArchiveImpl
 */
class SourceArchiveImpl : public SourceArchive {
private:
    UniversalID sourceArchiveID_;
    std::string domainFileID_;
    ArchiveType archiveType_;
    std::string name_;
    int64_t lastSyncTime_;
    bool dirty_;

public:
    SourceArchiveImpl(UniversalID sourceArchiveID, ArchiveType type, const std::string& name);

    SourceArchiveImpl(UniversalID sourceArchiveID, const std::string& domainFileID,
                      ArchiveType type, const std::string& name);

    SourceArchiveImpl(UniversalID sourceArchiveID, const std::string& domainFileID,
                      ArchiveType type, const std::string& name, int64_t lastSyncTime, bool dirty);

    UniversalID getSourceArchiveID() const override { return sourceArchiveID_; }

    std::string getDomainFileID() const override { return domainFileID_; }

    ArchiveType getArchiveType() const override { return archiveType_; }

    std::string getName() const override { return name_; }

    int64_t getLastSyncTime() const override { return lastSyncTime_; }

    bool isDirty() const override { return dirty_; }

    void setLastSyncTime(int64_t time) override { lastSyncTime_ = time; }

    void setName(const std::string& name) override { name_ = name; }

    void setDirtyFlag(bool dirty) override { dirty_ = dirty; }

    void setSourceArchiveID(UniversalID id) { sourceArchiveID_ = id; }

    void setDomainFileID(const std::string& id) { domainFileID_ = id; }
};

} // namespace ghidra
