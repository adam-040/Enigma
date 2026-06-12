#include "ghidra/MenuResourceDataType.h"
#include <typeinfo>

namespace ghidra {

MenuResourceDataType::MenuResourceDataType()
    : MenuResourceDataType(nullptr) {}

MenuResourceDataType::MenuResourceDataType(DataTypeManager* dtm)
    : DynamicDataType("MenuResource", dtm) {}

std::string MenuResourceDataType::getDescription() const {
    return "Menu stored as a Resource";
}

std::string MenuResourceDataType::getMnemonic(Settings* settings) const {
    return "MenuRes";
}

std::string MenuResourceDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<Menu-Resource>";
}

const std::type_info& MenuResourceDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* MenuResourceDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<MenuResourceDataType*>(this);
    }
    return new MenuResourceDataType(dtm);
}

std::vector<DataTypeComponent*> MenuResourceDataType::getAllComponents(MemBuffer* buf) {
    return {};
}

} // namespace ghidra
