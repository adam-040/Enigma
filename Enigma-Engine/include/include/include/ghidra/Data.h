/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Data.h
/// \brief Data representation in the program listing
/// Translated from: ghidra.program.model.listing.Data
#pragma once

#include <ghidra/CodeUnit.h>
#include <string>
#include <vector>

namespace ghidra {

class Data : public CodeUnit {
public:
    Data() = default;
    Data(Program* program, Address address, DataType* dataType, int length);

    int getLength() const override;

    DataType* getBaseDataType() const;

    int getNumComponents() const;

    Data* getComponent(int index) const;
    void addComponent(Data* component);

    Data* getParent() const { return parent_; }
    void setParent(Data* parent) { parent_ = parent; }

    int getComponentOffset() const { return componentOffset_; }
    void setComponentOffset(int offset) { componentOffset_ = offset; }

    bool isPointer() const;
    bool isString() const;
    bool isUnicode() const;
    bool isArray() const;
    bool isStructure() const;
    bool isUnion() const;

    std::string getDefaultLabelRepresentation() const;
    std::string toString() const override;

    Data* getPrimitiveAt(int offset) const;
    bool isDefined() const;

private:
    int length_ = 0;
    Data* parent_ = nullptr;
    int componentOffset_ = 0;
    std::vector<Data*> components_;
};

} // namespace ghidra
