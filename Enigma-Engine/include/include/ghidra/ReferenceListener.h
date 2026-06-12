/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ReferenceListener.h
/// \brief Listener interface for reference changes
/// Translated from: ghidra.program.model.symbol.ReferenceListener
#pragma once

#include <ghidra/Reference.h>

namespace ghidra {

class ReferenceListener {
public:
    virtual ~ReferenceListener() = default;

    virtual void memReferenceAdded(Reference* ref) = 0;
    virtual void memReferenceRemoved(Reference* ref) = 0;
    virtual void memReferenceTypeChanged(Reference* newRef, Reference* oldRef) = 0;
    virtual void memReferencePrimarySet(Reference* ref) = 0;
    virtual void memReferencePrimaryRemoved(Reference* ref) = 0;
    virtual void stackReferenceAdded(Reference* ref) = 0;
    virtual void stackReferenceRemoved(Reference* ref) = 0;
    virtual void externalReferenceAdded(Reference* ref) = 0;
    virtual void externalReferenceRemoved(Reference* ref) = 0;
    virtual void externalReferenceNameChanged(Reference* ref) = 0;
};

} // namespace ghidra
