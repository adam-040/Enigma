#include "ghidra/DialogResourceDataType.h"
#include <typeinfo>

namespace ghidra {

DialogResourceDataType::DialogResourceDataType()
    : DialogResourceDataType(nullptr) {}

DialogResourceDataType::DialogResourceDataType(DataTypeManager* dtm)
    : DynamicDataType("DialogResource", dtm) {}

std::string DialogResourceDataType::getDescription() const {
    return "Dialog stored as a Resource";
}

std::string DialogResourceDataType::getMnemonic(Settings* settings) const {
    return "DialogRes";
}

std::string DialogResourceDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<Dialog-Resource>";
}

const std::type_info& DialogResourceDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* DialogResourceDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<DialogResourceDataType*>(this);
    }
    return new DialogResourceDataType(dtm);
}

std::vector<DataTypeComponent*> DialogResourceDataType::getAllComponents(MemBuffer* buf) {
    return {};
}

} // namespace ghidra
