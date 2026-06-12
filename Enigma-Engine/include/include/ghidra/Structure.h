/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Structure.h
/// \brief The structure interface.
#pragma once

#include "Composite.h"

namespace ghidra {

/**
 * The structure interface.
 * Translated from: ghidra.program.model.data.Structure
 */
class Structure : public virtual Composite {
public:
    virtual ~Structure() = default;

    virtual Structure* clone(DataTypeManager* dtm) const = 0;

    virtual DataTypeComponent* getDefinedComponentAtOrAfterOffset(int offset) const = 0;

    virtual DataTypeComponent* getComponentContaining(int offset) const = 0;

    virtual DataTypeComponent* getComponentAt(int offset) const {
        DataTypeComponent* dtc = getComponentContaining(offset);
        while (dtc != nullptr && dtc->isBitFieldComponent() && dtc->getOffset() < offset &&
               dtc->getOrdinal() < (getNumComponents() - 1)) {
            dtc = getComponent(dtc->getOrdinal() + 1);
        }
        if (dtc != nullptr && dtc->getOffset() == offset) {
            return dtc;
        }
        return nullptr;
    }

    virtual std::vector<DataTypeComponent*> getComponentsContaining(int offset) const = 0;

    virtual DataTypeComponent* getDataTypeAt(int offset) const = 0;

    virtual DataTypeComponent* insertBitField(int ordinal, int byteWidth, int bitOffset,
                                              DataType* baseDataType, int bitSize, 
                                              const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* insertBitFieldAt(int byteOffset, int byteWidth, int bitOffset,
                                                DataType* baseDataType, int bitSize, 
                                                const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* insertAtOffset(int offset, DataType* dataType, int length) = 0;

    virtual DataTypeComponent* insertAtOffset(int offset, DataType* dataType, int length,
                                              const std::string& componentName, const std::string& comment) = 0;

    virtual void deleteAtOffset(int offset) = 0;

    virtual void deleteAll() = 0;

    virtual void clearAtOffset(int offset) = 0;

    virtual void clearComponent(int ordinal) = 0;

    virtual DataTypeComponent* replace(int ordinal, DataType* dataType, int length) = 0;

    virtual DataTypeComponent* replace(int ordinal, DataType* dataType, int length,
                                       const std::string& componentName, const std::string& comment) = 0;

    virtual DataTypeComponent* replaceAtOffset(int offset, DataType* dataType, int length,
                                               const std::string& componentName, const std::string& comment) = 0;

    virtual void growStructure(int amount) = 0;

    virtual void setLength(int length) = 0;
};

} // namespace ghidra
