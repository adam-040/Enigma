/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceArchiveImpl.cpp
/// \brief In-memory implementation of SourceArchive for use by DataTypeManager
#include "ghidra/SourceArchiveImpl.h"

namespace ghidra {

SourceArchiveImpl::SourceArchiveImpl(UniversalID sourceArchiveID, ArchiveType type,
                                     const std::string& name)
    : sourceArchiveID_(sourceArchiveID),
      domainFileID_(""),
      archiveType_(type),
      name_(name),
      lastSyncTime_(0),
      dirty_(false) {}

SourceArchiveImpl::SourceArchiveImpl(UniversalID sourceArchiveID, const std::string& domainFileID,
                                     ArchiveType type, const std::string& name)
    : sourceArchiveID_(sourceArchiveID),
      domainFileID_(domainFileID),
      archiveType_(type),
      name_(name),
      lastSyncTime_(0),
      dirty_(false) {}

SourceArchiveImpl::SourceArchiveImpl(UniversalID sourceArchiveID, const std::string& domainFileID,
                                     ArchiveType type, const std::string& name,
                                     int64_t lastSyncTime, bool dirty)
    : sourceArchiveID_(sourceArchiveID),
      domainFileID_(domainFileID),
      archiveType_(type),
      name_(name),
      lastSyncTime_(lastSyncTime),
      dirty_(dirty) {}

} // namespace ghidra
