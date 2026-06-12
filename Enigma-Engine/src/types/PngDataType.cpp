#include "ghidra/PngDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include "ghidra/PngResource.h"
#include <typeinfo>

namespace ghidra {

PngDataType::PngDataType() : PngDataType(nullptr) {}

PngDataType::PngDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "PNG", dtm) {
}

std::string PngDataType::getDescription() const {
    return "PNG (Portable Network Graphics) image";
}

std::string PngDataType::getMnemonic(Settings* settings) const {
    return "png";
}

int PngDataType::getLength() const {
    return -1;
}

int PngDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        PngResource png(buf);
        return png.getLength();
    } catch (...) {
        return -1;
    }
}

std::string PngDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<PNG-Image>";
}

const std::type_info& PngDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* PngDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<PngDataType*>(this);
    }
    return new PngDataType(dtm);
}

DataType* PngDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* PngDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string PngDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "PNG";
}

bool PngDataType::isMagic(const uint8_t* data, int length) {
    return PngResource::isMagic(data, length);
}

} // namespace ghidra
