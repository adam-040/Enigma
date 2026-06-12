/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file VersionException.cpp
/// \brief Implementation of VersionException
#include "ghidra/VersionException.h"

namespace ghidra {

std::string VersionException::getDefaultMessage(bool upgradable) {
    if (upgradable) {
        return "data created with older software and requires upgrade";
    }
    return "data created with newer version and can not be read";
}

VersionException::VersionException()
    : UsrException(getDefaultMessage(false)) {}

VersionException::VersionException(bool upgradable)
    : UsrException(getDefaultMessage(upgradable)),
      upgradeable(upgradable),
      versionIndicator(upgradable ? OLDER_VERSION : UNKNOWN_VERSION) {}

VersionException::VersionException(int versionIndicator, bool upgradable)
    : VersionException(upgradable) {
    this->versionIndicator = versionIndicator;
}

VersionException& VersionException::combine(const VersionException& ve) {
    if (this->versionIndicator != ve.versionIndicator)
        versionIndicator = UNKNOWN_VERSION;
    upgradeable = upgradeable && ve.upgradeable;
    if (detailMessage.empty()) {
        detailMessage = ve.detailMessage;
    } else if (!ve.detailMessage.empty()) {
        detailMessage += "\n" + ve.detailMessage;
    }
    return *this;
}

} // namespace ghidra
