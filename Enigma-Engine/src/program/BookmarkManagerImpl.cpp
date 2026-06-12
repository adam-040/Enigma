/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BookmarkManagerImpl.cpp
/// \brief Implementation of bookmark manager
/// Translated from: ghidra.program.database.bookmark.BookmarkDBManager

#include <ghidra/BookmarkManagerImpl.h>

namespace ghidra {

Bookmark* BookmarkManagerImpl::setBookmark(Address addr, const std::string& type, const std::string& comment) {
    BookmarkKey key(addr, type);
    auto bm = std::make_unique<Bookmark>(addr, type, comment);
    Bookmark* raw = bm.get();
    bookmarks_[key] = std::move(bm);
    bookmarksByAddr_[addr.toString()].push_back(raw);
    bookmarksByType_[type].push_back(raw);
    return raw;
}

Bookmark* BookmarkManagerImpl::getBookmark(Address addr, const std::string& type) {
    BookmarkKey key(addr, type);
    auto it = bookmarks_.find(key);
    return (it != bookmarks_.end()) ? it->second.get() : nullptr;
}

std::vector<Bookmark*> BookmarkManagerImpl::getBookmarks(Address addr) {
    auto it = bookmarksByAddr_.find(addr.toString());
    return (it != bookmarksByAddr_.end()) ? it->second : std::vector<Bookmark*>{};
}

std::vector<Bookmark*> BookmarkManagerImpl::getBookmarks(const std::string& type) {
    auto it = bookmarksByType_.find(type);
    return (it != bookmarksByType_.end()) ? it->second : std::vector<Bookmark*>{};
}

bool BookmarkManagerImpl::removeBookmark(Address addr, const std::string& type) {
    BookmarkKey key(addr, type);
    return bookmarks_.erase(key) > 0;
}

std::vector<Bookmark*> BookmarkManagerImpl::getAllBookmarks() const {
    std::vector<Bookmark*> result;
    result.reserve(bookmarks_.size());
    for (const auto& pair : bookmarks_) {
        result.push_back(pair.second.get());
    }
    return result;
}

} // namespace ghidra
