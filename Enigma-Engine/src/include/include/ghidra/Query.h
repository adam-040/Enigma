/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Query.h
/// \brief Predicate interface for matching database records.
#pragma once

namespace ghidra {

/**
 * Predicate used to test a record for some condition.
 * Translated from: ghidra.program.database.util.Query
 *
 * The CLI port uses an opaque pointer (DBRecord-like) since
 * the in-memory program model does not have a database.
 */
class Query {
public:
    virtual ~Query() = default;
    virtual bool matches(const void* record) const = 0;
};

} // namespace ghidra
