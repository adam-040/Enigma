/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BookmarkManager.h
/// \brief Bookmark manager interface
/// Translated from: ghidra.program.model.bookmark.BookmarkManager
#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>

namespace ghidra {

class Bookmark {
public:
    Bookmark() = default;
    Bookmark(Address addr, const std::string& type, const std::string& comment)
        : address_(addr), type_(type), comment_(comment) {}

    Address getAddress() const { return address_; }
    const std::string& getType() const { return type_; }
    const std::string& getComment() const { return comment_; }

private:
    Address address_;
    std::string type_;
    std::string comment_;
};

class BookmarkManager {
public:
    virtual ~BookmarkManager() = default;

    virtual Bookmark* setBookmark(Address addr, const std::string& type, const std::string& comment) = 0;
    virtual Bookmark* getBookmark(Address addr, const std::string& type) = 0;
    virtual std::vector<Bookmark*> getBookmarks(Address addr) = 0;
    virtual std::vector<Bookmark*> getBookmarks(const std::string& type) = 0;
    virtual std::vector<Bookmark*> getAllBookmarks() const = 0;
    virtual bool removeBookmark(Address addr, const std::string& type) = 0;
    virtual int getBookmarkCount() = 0;
};

} // namespace ghidra
