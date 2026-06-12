#include "ghidra/UseropSymbol.h"
#include "ghidra/SleighLanguage.h"
#include "ghidra/ElementId.h"
#include "ghidra/AttributeId.h"

namespace ghidra {

void UseropSymbol::decodeHeader(Decoder* decoder) {
    int el = decoder->openElement();
    name_ = decoder->readString(ATTRIB_NAME);
    id_ = static_cast<int>(decoder->readUnsignedInteger(ATTRIB_ID));
    scopeId_ = static_cast<int>(decoder->readUnsignedInteger(ATTRIB_SCOPE));
    decoder->closeElement(el);
}

void UseropSymbol::decode(Decoder* decoder, SleighLanguage* sleigh) {
    index_ = decoder->readSignedInteger(ATTRIB_INDEX);
    decoder->closeElement(ELEM_USEROP.id);
}

} // namespace ghidra
