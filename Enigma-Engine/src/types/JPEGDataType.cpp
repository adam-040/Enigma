#include "ghidra/JPEGDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

JPEGDataType::JPEGDataType() : JPEGDataType(nullptr) {}

JPEGDataType::JPEGDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "JPEG", dtm) {
}

std::string JPEGDataType::getDescription() const {
    return "JPEG image";
}

std::string JPEGDataType::getMnemonic(Settings* settings) const {
    return "jpg";
}

int JPEGDataType::getLength() const {
    return -1;
}

int JPEGDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        if ((buf->getByte(0) & 0xFF) != 0xFF ||
            (buf->getByte(1) & 0xFF) != 0xD8 ||
            (buf->getByte(2) & 0xFF) != 0xFF) {
            return -1;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

std::string JPEGDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<JPEG-Image>";
}

const std::type_info& JPEGDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* JPEGDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<JPEGDataType*>(this);
    }
    return new JPEGDataType(dtm);
}

DataType* JPEGDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* JPEGDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string JPEGDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "JPEG";
}

bool JPEGDataType::isMagic(const uint8_t* data, int length) {
    if (length < 3) return false;
    return data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF;
}

} // namespace ghidra
