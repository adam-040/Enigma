/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file NoisyStructureBuilder.h
/// \brief Build a structure from a "noisy" source of field information.
#pragma once

#include "ghidra/Structure.h"
#include "ghidra/DataType.h"
#include <map>
#include <vector>

namespace ghidra {

/**
 * Build a structure from a "noisy" source of field information. Feed it field records
 * (via addDataType when we have definitive info, or addReference for pointer references).
 * Overlaps and conflicts are resolved; less specific data-types are replaced.
 * Translated from: ghidra.program.model.data.NoisyStructureBuilder
 */
class NoisyStructureBuilder {
public:
    NoisyStructureBuilder();
    virtual ~NoisyStructureBuilder() = default;

    void addDataType(int64_t offset, DataType* dt);
    void addReference(int64_t offset, DataType* dt);
    void openStruct(int64_t offset, DataType* dt);
    void openComponent(int64_t offset, int64_t size);
    void closeStruct(int64_t offset);

    Structure* getStruct(int64_t offset);
    const std::map<int64_t, DataType*>& getOffsetToDataTypeMap() const { return offsetToDataTypeMap_; }
    int getSize() const { return static_cast<int>(offsetToDataTypeMap_.size()); }

private:
    std::map<int64_t, DataType*> offsetToDataTypeMap_;
    std::map<int64_t, Structure*> structs_;
};

} // namespace ghidra
