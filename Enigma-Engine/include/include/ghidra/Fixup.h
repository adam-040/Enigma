/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Fixup.h
/// \brief Interface for a generic "fix" operation.
#pragma once

#include <string>

namespace ghidra {

class ServiceProvider;

/**
 * Describes a fixup action that can address an issue.
 * Translated from: ghidra.util.Fixup
 */
class Fixup {
public:
    virtual ~Fixup() = default;
    virtual std::string getDescription() const = 0;
    virtual bool canFixup() const = 0;
    virtual bool fixup(ServiceProvider* provider) = 0;
};

} // namespace ghidra
