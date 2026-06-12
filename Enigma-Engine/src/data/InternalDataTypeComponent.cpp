#include <ghidra/InternalDataTypeComponent.h>
#include <ghidra/BitFieldDataType.h>
#include <algorithm>
#include <sstream>

namespace ghidra {

std::string InternalDataTypeComponent::toString(const DataTypeComponent* c) {
    std::ostringstream buf;
    buf << "  " << c->getOrdinal();
    buf << "  " << c->getOffset();
    buf << "  " << c->getDataType()->getName();
    if (c->isBitFieldComponent()) {
        if (auto* bfDt = dynamic_cast<BitFieldDataType*>(c->getDataType())) {
            buf << "(" << bfDt->getBitOffset() << ")";
        }
    }
    buf << "  " << c->getLength();
    std::string name = c->getFieldName();
    buf << "  " << (name.empty() ? "" : name);
    std::string cmt = c->getComment();
    if (!cmt.empty()) {
        buf << "  \"" << cmt << "\"";
    }
    return buf.str();
}

std::string InternalDataTypeComponent::cleanupFieldName(const std::string& name) {
    if (name.empty()) return {};

    // Trim leading/trailing whitespace
    auto start = name.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) return {};

    auto end = name.find_last_not_of(" \t\n\r\f\v");
    std::string fieldName = name.substr(start, end - start + 1);

    // Replace internal whitespace with underscores
    for (auto& c : fieldName) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            c = '_';
        }
    }
    return fieldName;
}

} // namespace ghidra
