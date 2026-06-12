/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file SourceFileManager.h
/// \brief Source file manager interface and SourceFile value class
/// Translated from: ghidra.program.model.sourcemap.SourceFileManager
#pragma once

#include <ghidra/SourceFileIdType.h>
#include <ghidra/SourceMapEntry.h>
#include <ghidra/SourceMapEntryIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressOverflowException.h>
#include <ghidra/LockException.h>
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <memory>

namespace ghidra {

class SourceFile {
public:
    SourceFile() : idType_(SourceFileIdType::NONE) {}
    
    SourceFile(const std::string& path, const std::string& compilerSpec)
        : path_(path), compilerSpec_(compilerSpec), idType_(SourceFileIdType::NONE) {}

    SourceFile(const std::string& path, SourceFileIdType idType,
               const std::vector<uint8_t>& identifier,
               const std::string& compilerSpec = "")
        : path_(path), compilerSpec_(compilerSpec), idType_(idType), identifier_(identifier) {}

    const std::string& getPath() const { return path_; }
    const std::string& getCompilerSpec() const { return compilerSpec_; }
    SourceFileIdType getIdType() const { return idType_; }
    const std::vector<uint8_t>& getIdentifier() const { return identifier_; }

    std::string getFilename() const {
        size_t pos = path_.find_last_of("/\\");
        if (pos == std::string::npos) return path_;
        return path_.substr(pos + 1);
    }

    std::string getIdAsString() const {
        if (idType_ == SourceFileIdType::NONE || idType_ == SourceFileIdType::UNKNOWN) {
            return "";
        }
        if (idType_ == SourceFileIdType::TIMESTAMP_64 && identifier_.size() == 8) {
            uint64_t ms = 0;
            for (int i = 0; i < 8; ++i) {
                ms = (ms << 8) | identifier_[i];
            }
            std::time_t sec = static_cast<std::time_t>(ms / 1000);
            char buf[64];
            struct tm gmt;
#ifdef _WIN32
            gmtime_s(&gmt, &sec);
#else
            gmtime_r(&sec, &gmt);
#endif
            std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &gmt);
            return std::string(buf);
        }
        std::string hex;
        hex.reserve(identifier_.size() * 2);
        static const char* const lut = "0123456789abcdef";
        for (uint8_t b : identifier_) {
            hex.push_back(lut[b >> 4]);
            hex.push_back(lut[b & 15]);
        }
        return hex;
    }

    int compareTo(const SourceFile& other) const {
        int comp = path_.compare(other.path_);
        if (comp != 0) return comp;
        if (idType_ < other.idType_) return -1;
        if (idType_ > other.idType_) return 1;
        if (identifier_ < other.identifier_) return -1;
        if (identifier_ > other.identifier_) return 1;
        return 0;
    }

    bool operator==(const SourceFile& other) const {
        return path_ == other.path_ && idType_ == other.idType_ && identifier_ == other.identifier_;
    }

    bool operator!=(const SourceFile& other) const {
        return !(*this == other);
    }

private:
    std::string path_;
    std::string compilerSpec_;
    SourceFileIdType idType_ = SourceFileIdType::NONE;
    std::vector<uint8_t> identifier_;
};

class SourceFileManager {
public:
    virtual ~SourceFileManager() = default;

    // Legacy path-based interface
    virtual SourceFile* addSourceFile(const std::string& path,
                                     const std::string& compilerSpec) = 0;
    virtual SourceFile* getSourceFile(const std::string& path) = 0;
    virtual std::vector<SourceFile*> getSourceFiles() = 0;
    virtual int getSourceFileCount() = 0;

    // Rich source mapping interface
    virtual std::vector<SourceMapEntry> getSourceMapEntries(const Address& addr) = 0;

    virtual SourceMapEntry addSourceMapEntry(SourceFile* sourceFile, int lineNumber,
                                             const Address& baseAddr, uint64_t length) = 0;
    virtual bool intersectsSourceMapEntry(const AddressSetView& addrs) = 0;

    virtual bool addSourceFile(SourceFile* sourceFile) = 0;
    virtual bool removeSourceFile(SourceFile* sourceFile) = 0;
    virtual bool containsSourceFile(SourceFile* sourceFile) = 0;

    virtual std::vector<SourceFile*> getAllSourceFiles() = 0;
    virtual std::vector<SourceFile*> getMappedSourceFiles() = 0;

    virtual void transferSourceMapEntries(SourceFile* source, SourceFile* target) = 0;
    virtual SourceMapEntryIterator getSourceMapEntryIterator(const Address& address,
                                                             bool forward) = 0;

    virtual std::vector<SourceMapEntry> getSourceMapEntries(SourceFile* sourceFile,
                                                            int minLine, int maxLine) = 0;
    virtual bool removeSourceMapEntry(const SourceMapEntry& entry) = 0;
};

} // namespace ghidra
