/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file InvalidatedListener.h
/// \brief Listener interface for DataTypeManager cache invalidation events.
#pragma once

namespace ghidra {

class DataTypeManager;

/**
 * Listener interface for DataTypeManager cache invalidation.
 * Translated from: ghidra.program.model.data.InvalidatedListener
 */
class InvalidatedListener {
public:
    virtual ~InvalidatedListener() = default;
    virtual void dataTypeManagerInvalidated(DataTypeManager* dataTypeManager) = 0;
};

} // namespace ghidra
