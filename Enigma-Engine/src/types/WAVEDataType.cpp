#include "ghidra/WAVEDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

WAVEDataType::WAVEDataType() : WAVEDataType(nullptr) {}

WAVEDataType::WAVEDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "WAVE", dtm) {
}

std::string WAVEDataType::getDescription() const {
    return "WAVE audio";
}

std::string WAVEDataType::getMnemonic(Settings* settings) const {
    return "wav";
}

int WAVEDataType::getLength() const {
    return -1;
}

int WAVEDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        static const uint8_t MAGIC[] = { 'R', 'I', 'F', 'F' };
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(i) & 0xFF) != MAGIC[i]) return -1;
        }
        int size = buf->getInt(4);
        if (size <= 0) return -1;
        static const uint8_t WAVE_ID[] = { 'W', 'A', 'V', 'E' };
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(8 + i) & 0xFF) != WAVE_ID[i]) return -1;
        }
        return size + 8;
    } catch (...) {
        return -1;
    }
}

std::string WAVEDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<WAVE-Resource>";
}

const std::type_info& WAVEDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* WAVEDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<WAVEDataType*>(this);
    }
    return new WAVEDataType(dtm);
}

DataType* WAVEDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* WAVEDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string WAVEDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "WAVE";
}

bool WAVEDataType::isMagic(const uint8_t* data, int length) {
    if (length < 12) return false;
    static const uint8_t MAGIC[] = { 'R', 'I', 'F', 'F' };
    static const uint8_t WAVE_ID[] = { 'W', 'A', 'V', 'E' };
    for (int i = 0; i < 4; i++) {
        if (data[i] != MAGIC[i]) return false;
    }
    for (int i = 0; i < 4; i++) {
        if (data[8 + i] != WAVE_ID[i]) return false;
    }
    return true;
}

} // namespace ghidra
