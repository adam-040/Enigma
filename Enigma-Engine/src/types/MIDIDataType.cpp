#include "ghidra/MIDIDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"
#include <typeinfo>

namespace ghidra {

MIDIDataType::MIDIDataType() : MIDIDataType(nullptr) {}

MIDIDataType::MIDIDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath(), "MIDI", dtm) {
}

std::string MIDIDataType::getDescription() const {
    return "MIDI audio";
}

std::string MIDIDataType::getMnemonic(Settings* settings) const {
    return "midi";
}

int MIDIDataType::getLength() const {
    return -1;
}

int MIDIDataType::getLength(MemBuffer* buf, int maxLength) {
    if (!buf) return -1;
    try {
        static const uint8_t MAGIC[] = { 'M', 'T', 'h', 'd' };
        for (int i = 0; i < 4; i++) {
            if ((buf->getByte(i) & 0xFF) != MAGIC[i]) return -1;
        }
        return 14;
    } catch (...) {
        return -1;
    }
}

std::string MIDIDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    return "<MIDI-Resource>";
}

const std::type_info& MIDIDataType::getValueClass(Settings* settings) const {
    return typeid(std::string);
}

DataType* MIDIDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<MIDIDataType*>(this);
    }
    return new MIDIDataType(dtm);
}

DataType* MIDIDataType::getReplacementBaseType() const {
    return &ByteDataType::dataType();
}

DataType* MIDIDataType::getReplacementBaseType() {
    return &ByteDataType::dataType();
}

std::string MIDIDataType::getCTypeDeclaration(DataOrganization* dataOrganization) {
    return "MIDI";
}

bool MIDIDataType::isMagic(const uint8_t* data, int length) {
    if (length < 4) return false;
    static const uint8_t MAGIC[] = { 'M', 'T', 'h', 'd' };
    for (int i = 0; i < 4; i++) {
        if (data[i] != MAGIC[i]) return false;
    }
    return true;
}

} // namespace ghidra
