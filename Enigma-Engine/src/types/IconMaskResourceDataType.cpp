#include "ghidra/IconMaskResourceDataType.h"

namespace ghidra {

IconMaskResourceDataType::IconMaskResourceDataType()
    : IconMaskResourceDataType(nullptr) {}

IconMaskResourceDataType::IconMaskResourceDataType(DataTypeManager* dtm)
    : IconMaskResourceDataType(CategoryPath(), "IconMaskResource", dtm) {}

IconMaskResourceDataType::IconMaskResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : IconResourceDataType(path, name, dtm) {}

std::string IconMaskResourceDataType::getDescription() const {
    return "Icon with Mask stored as a Resource";
}

std::string IconMaskResourceDataType::getMnemonic(Settings* settings) const {
    return "IconMaskRes";
}

DataType* IconMaskResourceDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<IconMaskResourceDataType*>(this);
    }
    return new IconMaskResourceDataType(dtm);
}

} // namespace ghidra
