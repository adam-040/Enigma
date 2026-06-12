/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file MacintoshTimeStampDataType.cpp
/// \brief Mac OS timestamp data type implementation
#include "ghidra/MacintoshTimeStampDataType.h"
#include "ghidra/MemBuffer.h"
#include <ctime>
#include <sstream>
#include <cstdint>

namespace ghidra {

MacintoshTimeStampDataType::MacintoshTimeStampDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "MacTime", dtm) {}

std::string MacintoshTimeStampDataType::getDescription() const {
    return "The stamp follows the Macintosh time-measurement scheme "
        "(that is, the number of seconds measured from January 1, 1904).";
}

int MacintoshTimeStampDataType::getLength() const {
    return 4;
}

std::string MacintoshTimeStampDataType::getMnemonic(Settings* settings) const {
    return "MacTime";
}

std::string MacintoshTimeStampDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    uint32_t macSeconds;
    try {
        macSeconds = static_cast<uint32_t>(buf->getInt(0));
    } catch (...) {
        return "";
    }

    // Mac epoch: Jan 1, 1904. Unix epoch: Jan 1, 1970.
    // 2082844800 seconds between these dates.
    uint64_t unixSeconds = static_cast<uint64_t>(macSeconds);
    if (unixSeconds < 2082844800ULL) {
        return "";
    }
    unixSeconds -= 2082844800ULL;

    time_t t = static_cast<time_t>(unixSeconds);
    std::tm* gmt = std::gmtime(&t);
    if (!gmt) return "";

    char dateBuf[64];
    std::strftime(dateBuf, sizeof(dateBuf), "%d-%b-%Y %H:%M:%S", gmt);
    return std::string(dateBuf);
}

const std::type_info& MacintoshTimeStampDataType::getValueClass(Settings* settings) const {
    return typeid(uint32_t);
}

DataType* MacintoshTimeStampDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<MacintoshTimeStampDataType*>(this);
    }
    return new MacintoshTimeStampDataType(dtm);
}

} // namespace ghidra
