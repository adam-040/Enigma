/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OrQuery.h
/// \brief Logical-OR composition of two Query predicates.
#pragma once

#include "ghidra/Query.h"
#include <memory>

namespace ghidra {

/**
 * Combines two queries such that this query is the logical "OR" of the two queries.
 * Translated from: ghidra.program.database.util.OrQuery
 */
class OrQuery : public Query {
public:
    OrQuery(std::unique_ptr<Query> q1, std::unique_ptr<Query> q2);

    bool matches(const void* record) const override;

private:
    std::unique_ptr<Query> q1_;
    std::unique_ptr<Query> q2_;
};

} // namespace ghidra
