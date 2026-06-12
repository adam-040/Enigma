/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BookmarkType.h
/// \file BookmarkType.h
/// \file BookmarkType.h
/// \brief Bookmark type enumeration
/// Translated from: ghidra.program.model.listing.BookmarkType
#pragma once

#include <string>
#include <unordered_map>

namespace ghidra {

enum class BookmarkType {
    NOTE,
    WARNING,
    ERROR,
    INFO,
    ANALYSIS
};

inline std::string bookmarkTypeToString(BookmarkType type) {
    switch (type) {
        case BookmarkType::NOTE: return "Note";
        case BookmarkType::WARNING: return "Warning";
        case BookmarkType::ERROR: return "Error";
        case BookmarkType::INFO: return "Info";
        case BookmarkType::ANALYSIS: return "Analysis";
    }
    return "Unknown";
}

inline BookmarkType parseBookmarkType(const std::string& str) {
    static const std::unordered_map<std::string, BookmarkType> map = {
        {"Note", BookmarkType::NOTE},
        {"Warning", BookmarkType::WARNING},
        {"Error", BookmarkType::ERROR},
        {"Info", BookmarkType::INFO},
        {"Analysis", BookmarkType::ANALYSIS}
    };
    auto it = map.find(str);
    return (it != map.end()) ? it->second : BookmarkType::NOTE;
}

} // namespace ghidra
