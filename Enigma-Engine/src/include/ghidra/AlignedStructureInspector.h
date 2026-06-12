/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AlignedStructureInspector.h
/// \brief Read-only aligned structure packing inspector.
/// Translated from: ghidra.program.model.data.AlignedStructureInspector
#pragma once

#include "AlignedStructurePacker.h"
#include "InternalDataTypeComponent.h"
#include "DataTypeComponent.h"
#include "Settings.h"
#include <vector>
#include <stdexcept>

namespace ghidra {

class Structure;

class AlignedStructureInspector : public AlignedStructurePacker {
private:
    class ReadOnlyComponentWrapper : public InternalDataTypeComponent {
    public:
        ReadOnlyComponentWrapper(DataTypeComponent* component);

        DataType* getDataType() const override;
        DataType* getParent() const override;
        bool isBitFieldComponent() const override;
        bool isZeroBitFieldComponent() const override;
        int getOrdinal() const override;
        int getOffset() const override;
        int getEndOffset() const override;
        int getLength() const override;
        std::string getComment() const override;
        Settings* getDefaultSettings() const override;
        DataTypeComponent* setComment(const std::string& comment) override;
        std::string getFieldName() const override;
        DataTypeComponent* setFieldName(const std::string& fieldName) override;
        bool isEquivalent(const DataTypeComponent* dtc) const override;
        bool isUndefined() const override;
        void setDataType(DataType* dataType) override;
        void update(int ordinal, int offset, int length) override;

    private:
        DataTypeComponent* component_;
        int ordinal_;
        int offset_;
        int length_;
        DataType* dataType_;
    };

    explicit AlignedStructureInspector(StructureInternal* structure);

    static std::vector<InternalDataTypeComponent*> getComponentWrappers(Structure* structure);

public:
    static StructurePackResult packComponents(StructureInternal* structure);
};

} // namespace ghidra
