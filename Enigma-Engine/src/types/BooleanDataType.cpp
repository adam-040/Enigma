/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra\BooleanDataType.h>

namespace ghidra {

BooleanDataType& BooleanDataType::dataType() {
    static BooleanDataType instance;
    return instance;
}

BooleanDataType::BooleanDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "bool", dtm) {
}

std::string BooleanDataType::getMnemonic(Settings* settings) const {
    return "bool";
}

std::string BooleanDataType::getDecompilerDisplayName() const {
    return name_;
}

int BooleanDataType::getLength() const {
    return 1;
}

int BooleanDataType::getAlignedLength() const {
    return 1;
}

std::string BooleanDataType::getDescription() const {
    return "Boolean";
}

const std::type_info& BooleanDataType::getValueClass(Settings* settings) const {
    return typeid(bool);
}

std::string BooleanDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "??";
}

DataType* BooleanDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<BooleanDataType*>(this);
    }
    return new BooleanDataType(dtm);
}

std::string BooleanDataType::getDefaultLabelPrefix() const {
    return "BOOL";
}

} // namespace ghidra
