/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file BookmarkManagerImpl.h
/// \brief Implementation of bookmark manager
/// Translated from: ghidra.program.database.bookmark.BookmarkDBManager
#pragma once

#include <ghidra/BookmarkManager.h>
#include <ghidra/ManagerDB.h>
#include <vector>
#include <unordered_map>
#include <memory>

namespace ghidra {

class Program;
class TaskMonitor;

class BookmarkManagerImpl : public BookmarkManager, public ManagerDB {
public:
    BookmarkManagerImpl() = default;
    explicit BookmarkManagerImpl(Program* program) : program_(program) {}

    void setProgram(Program* program) override { program_ = program; }
    void programReady(int openMode, int currentRevision, TaskMonitor* monitor) override {}
    void clearCache(bool all) override { if (all) { bookmarks_.clear(); bookmarksByAddr_.clear(); bookmarksByType_.clear(); } }
    void deleteAddressRange(const Address& startAddr, const Address& endAddr, TaskMonitor* monitor) override {}
    void moveAddressRange(const Address& fromAddr, const Address& toAddr, uint64_t length, TaskMonitor* monitor) override {}
    int getNumEntries() override { return getBookmarkCount(); }
    int getRevision() override { return revision_; }
    void setRevision(int revision) override { revision_ = revision; }
    void invalidateCache(bool all) override { clearCache(all); }
    std::string getName() const override { return "BookmarkManager"; }

    Bookmark* setBookmark(Address addr, const std::string& type, const std::string& comment) override;

    Bookmark* getBookmark(Address addr, const std::string& type) override;

    std::vector<Bookmark*> getBookmarks(Address addr) override;

    std::vector<Bookmark*> getBookmarks(const std::string& type) override;

    std::vector<Bookmark*> getAllBookmarks() const override;

    bool removeBookmark(Address addr, const std::string& type) override;

    int getBookmarkCount() override { return static_cast<int>(bookmarks_.size()); }

private:
    struct BookmarkKey {
        Address addr;
        std::string type;
        BookmarkKey(const Address& a, const std::string& t) : addr(a), type(t) {}
        bool operator==(const BookmarkKey& other) const { return addr == other.addr && type == other.type; }
    };

    struct BookmarkKeyHash {
        size_t operator()(const BookmarkKey& k) const {
            return std::hash<std::string>{}(k.addr.toString()) ^ std::hash<std::string>{}(k.type);
        }
    };

    Program* program_ = nullptr;
    std::unordered_map<BookmarkKey, std::unique_ptr<Bookmark>, BookmarkKeyHash> bookmarks_;
    std::unordered_map<std::string, std::vector<Bookmark*>> bookmarksByAddr_;
    std::unordered_map<std::string, std::vector<Bookmark*>> bookmarksByType_;
    int revision_ = 0;
};

} // namespace ghidra
