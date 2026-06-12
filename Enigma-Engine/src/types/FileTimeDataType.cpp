/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FileTimeDataType.cpp
/// \brief FileTime timestamp data type implementation
#include "ghidra/FileTimeDataType.h"
#include "ghidra/MemBuffer.h"
#include <ctime>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace ghidra {

FileTimeDataType::FileTimeDataType(DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), "FileTime", dtm) {}

std::string FileTimeDataType::getDescription() const {
    return "The stamp follows the Filetime-measurement scheme "
        "(that is, the number of 100 nanosecond ticks measured from midnight January 1, 1601).";
}

int FileTimeDataType::getLength() const {
    return 8;
}

std::string FileTimeDataType::getMnemonic(Settings* settings) const {
    return "FileTime";
}

std::string FileTimeDataType::getRepresentation(MemBuffer* buf, Settings* settings, int length) const {
    uint64_t ticks;
    try {
        ticks = static_cast<uint64_t>(buf->getLong(0));
    } catch (...) {
        return "";
    }

    // FileTime epoch: Jan 1, 1601. Unix epoch: Jan 1, 1970.
    // 11644473600 seconds between these dates.
    // 1 tick = 100 ns = 10^-7 seconds
    uint64_t unixSeconds = ticks / 10000000ULL;
    if (unixSeconds < 11644473600ULL) {
        return "";
    }
    unixSeconds -= 11644473600ULL;

    uint64_t fracTicks = ticks % 10000000ULL; // 0-9999999 (sub-second fraction)

    time_t t = static_cast<time_t>(unixSeconds);
    std::tm* gmt = std::gmtime(&t);
    if (!gmt) return "";

    char dateBuf[64];
    std::strftime(dateBuf, sizeof(dateBuf), "%Y-%m-%d %H:%M:%S", gmt);

    std::ostringstream oss;
    oss << dateBuf << "."
        << std::setw(7) << std::setfill('0') << fracTicks
        << " UTC";
    return oss.str();
}

const std::type_info& FileTimeDataType::getValueClass(Settings* settings) const {
    return typeid(uint64_t);
}

DataType* FileTimeDataType::clone(DataTypeManager* dtm) const {
    if (dtm == getDataTypeManager()) {
        return const_cast<FileTimeDataType*>(this);
    }
    return new FileTimeDataType(dtm);
}

} // namespace ghidra
