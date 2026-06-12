#include "ghidra/IconResourceDataType.h"
#include "ghidra/IconResource.h"
#include "ghidra/DataTypeComponent.h"
#include "ghidra/ReadOnlyDataTypeComponent.h"
#include "ghidra/ByteDataType.h"
#include "ghidra/ArrayDataType.h"
#include <typeinfo>

namespace ghidra {

IconResourceDataType::IconResourceDataType()
    : IconResourceDataType(nullptr) {}

IconResourceDataType::IconResourceDataType(DataTypeManager* dtm)
    : IconResourceDataType(CategoryPath(), "IconResource", dtm) {}

IconResourceDataType::IconResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : BitmapResourceDataType(path, name, dtm) {}

std::string IconResourceDataType::getDescription() const {
    return "Icon stored as a Resource";
}

std::string IconResourceDataType::getMnemonic(Settings* settings) const {
    return "IconRes";
}

std::string IconResourceDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<Icon-Image>";
}

const std::type_info& IconResourceDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* IconResourceDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<IconResourceDataType*>(this);
    }
    return new IconResourceDataType(dtm);
}

BitmapResource* IconResourceDataType::getBitmapResource(MemBuffer* buf) {
    try {
        return new IconResource(buf);
    } catch (...) {
        return nullptr;
    }
}

int IconResourceDataType::addComponents(MemBuffer* buf, BitmapResource* bmr,
                                         std::vector<DataTypeComponent*>& comps) {
    int offset = BitmapResourceDataType::addComponents(buf, bmr, comps);
    int arraySize = bmr->getMaskLength();
    if (arraySize > 0) {
        ArrayDataType array(&ByteDataType::dataType(), arraySize, 1);
        comps.push_back(new ReadOnlyDataTypeComponent(&array, this, arraySize, comps.size(), offset, "BitMask", nullptr));
        offset += arraySize;
    }
    return offset;
}

} // namespace ghidra
