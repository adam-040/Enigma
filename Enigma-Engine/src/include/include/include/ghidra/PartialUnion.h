/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PartialUnion.h
/// \brief Data-type representing an unspecified piece of a parent Union data-type.
/// Translated from: ghidra.program.model.pcode.PartialUnion
#pragma once

#include "ghidra/AbstractDataType.h"
#include "ghidra/CategoryPath.h"
#include "ghidra/Settings.h"
#include "ghidra/SettingsDefinition.h"
#include "ghidra/MemBuffer.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class DataType;
class Union;

/**
 * A data-type representing an unspecified piece of a parent Union data-type.
 * Used internally by the decompiler to label Varnodes representing partial
 * symbols where the part is known to be contained in a Union data-type.
 */
class PartialUnion : public AbstractDataType {
private:
    DataType* unionDataType;
    int offset;
    int size;

public:
    PartialUnion(DataTypeManager* dtm, DataType* parent, int off, int sz);

    /// @return the Union data-type of which this is a part
    DataType* getParent() const { return unionDataType; }

    /// @return the offset, in bytes, of this part within its parent Union
    int getOffset() const { return offset; }

    DataType* clone(DataTypeManager* dtm) const override;
    int getLength() const override;
    int getAlignedLength() const override;
    std::string getDescription() const override;
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    std::vector<SettingsDefinition*> getSettingsDefinitions() const override;
    Settings* getDefaultSettings() const override;
    DataType* copy(DataTypeManager* dtm) const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    bool isEquivalent(const DataType* dt) const override;
    int getAlignment() const override;

    /// Get a data-type that can be used as a formal replacement for this (internal) data-type
    DataType* getStrippedDataType() const;
};

} // namespace ghidra
