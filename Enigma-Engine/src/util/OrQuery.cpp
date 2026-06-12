/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file OrQuery.cpp
/// \brief Logical-OR composition of two Query predicates.
#include "ghidra/OrQuery.h"

namespace ghidra {

OrQuery::OrQuery(std::unique_ptr<Query> q1, std::unique_ptr<Query> q2)
    : q1_(std::move(q1)), q2_(std::move(q2)) {}

bool OrQuery::matches(const void* record) const {
    return q1_->matches(record) || q2_->matches(record);
}

} // namespace ghidra
