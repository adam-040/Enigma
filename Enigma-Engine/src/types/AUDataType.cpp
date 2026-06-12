#include "ghidra/AUDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

AUDataType::AUDataType() : AUDataType(nullptr) {}

AUDataType::AUDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "AU", dtm) {
}

std::string AUDataType::getDescription() const {
    return "AU (Sun \xE2\x88\xAB-law) audio";
}

std::string AUDataType::getMnemonic(Settings* settings) const {
    return "au";
}

int AUDataType::getLength() const {
    return -1;
}

int AUDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        static const uint8_t MAGIC[] = { '.', 's', 'n', 'd' };
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(i) & 0xFF) != MAGIC[i]) return -1;
        }
        int dataOffset = buf->getInt(4);
        int dataSize = buf->getInt(8);
        if (dataOffset <= 0 || dataSize < 0) return -1;
        return dataOffset + dataSize;
    } catch (...) {
        return -1;
    }
}

std::string AUDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<AU-Representation>";
}

const std::type_info& AUDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* AUDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<AUDataType*>(this);
    }
    return new AUDataType(dtm);
}

DataType* AUDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* AUDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string AUDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "AU";
}

bool AUDataType::isMagic(const uint8_t* data, int length) {
    if (length < 4) return false;
    static const uint8_t MAGIC[] = { '.', 's', 'n', 'd' };
    for (int i = 0; i < 4; i++) {
        if (data[i] != MAGIC[i]) return false;
    }
    return true;
}

} // namespace ghidra
