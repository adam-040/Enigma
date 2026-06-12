#include "ghidra/GifDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include "ghidra/GIFResource.h"
#include <typeinfo>

namespace ghidra {

GifDataType::GifDataType() : GifDataType(nullptr) {}

GifDataType::GifDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "GIF", dtm) {
}

std::string GifDataType::getDescription() const {
    return "GIF (Graphics Interchange Format) image";
}

std::string GifDataType::getMnemonic(Settings* settings) const {
    return "gif";
}

int GifDataType::getLength() const {
    return -1;
}

int GifDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    if (!GIFResource::isMagic(buf)) return -1;
    try {
        GIFResource gif(buf);
        return gif.getLength();
    } catch (...) {
        return -1;
    }
}

std::string GifDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<GIF-Image>";
}

const std::type_info& GifDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* GifDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<GifDataType*>(this);
    }
    return new GifDataType(dtm);
}

DataType* GifDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* GifDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string GifDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "GIF";
}

bool GifDataType::isMagic(const uint8_t* data, int length) {
    return GIFResource::isMagic(data, length);
}

} // namespace ghidra
