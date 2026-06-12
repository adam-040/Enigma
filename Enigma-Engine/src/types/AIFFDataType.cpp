#include "ghidra/AIFFDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

AIFFDataType::AIFFDataType() : AIFFDataType(nullptr) {}

AIFFDataType::AIFFDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "AIFF", dtm) {
}

std::string AIFFDataType::getDescription() const {
    return "AIFF (Audio Interchange File Format) audio";
}

std::string AIFFDataType::getMnemonic(Settings* settings) const {
    return "aiff";
}

int AIFFDataType::getLength() const {
    return -1;
}

int AIFFDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        static const uint8_t MAGIC[] = { 'F', 'O', 'R', 'M' };
        static const uint8_t AIFF_ID[] = { 'A', 'I', 'F', 'F' };
        bool valid = true;
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(i) & 0xFF) != MAGIC[i]) { valid = false; break; }
        }
        if (!valid) return -1;
        int size = buf->getInt(4);
        if (size <= 0) return -1;
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(8 + i) & 0xFF) != AIFF_ID[i]) { valid = false; break; }
        }
        if (!valid) return -1;
        return size + 8;
    } catch (...) {
        return -1;
    }
}

std::string AIFFDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<AIFF-Representation>";
}

const std::type_info& AIFFDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* AIFFDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<AIFFDataType*>(this);
    }
    return new AIFFDataType(dtm);
}

DataType* AIFFDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* AIFFDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string AIFFDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "AIFF";
}

bool AIFFDataType::isMagic(const uint8_t* data, int length) {
    if (length < 12) return false;
    static const uint8_t MAGIC[] = { 'F', 'O', 'R', 'M' };
    static const uint8_t AIFF_ID[] = { 'A', 'I', 'F', 'F' };
    for (int i = 0; i < 4; i++) {
        if (data[i] != MAGIC[i]) return false;
    }
    for (int i = 0; i < 4; i++) {
        if (data[8 + i] != AIFF_ID[i]) return false;
    }
    return true;
}

} // namespace ghidra
