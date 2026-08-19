/* ###
 * IP: Enigma Engine (original work)
 *
 * Minimal read-only ZIP archive reader (central directory + raw deflate
 * via zlib).  Used to open Ghidra .gzf exports which are plain zip files.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

/**
 * Read-only ZIP archive: parses the end-of-central-directory record and the
 * central directory, and supports member extraction.  Members stored with
 * method 0 (stored) or 8 (deflate) are supported.  Names use '/' separators
 * as found in Ghidra .gzf exports.
 */
class ZipArchive {
public:
    /** Parses an in-memory zip; throws std::runtime_error if invalid. */
    explicit ZipArchive(std::vector<uint8_t> bytes);

    /** Reads a zip file from disk and parses it. */
    static std::unique_ptr<ZipArchive> fromFile(const std::string& path);

    /** All member names (includes directory markers). */
    const std::vector<std::string>& entryNames() const;

    bool hasEntry(const std::string& name) const;

    /** Extracts the member; throws std::runtime_error if missing/unsupported. */
    std::vector<uint8_t> readEntry(const std::string& name) const;

private:
    struct Entry {
        uint32_t flags = 0;
        uint32_t method = 0;
        uint32_t compSize = 0;
        uint32_t uncompSize = 0;
        uint32_t localOffset = 0;
        bool isDirectory = false;
    };

    const Entry* find(const std::string& name) const;

    std::vector<uint8_t> bytes_;
    std::vector<std::string> names_;
    std::map<std::string, Entry> entries_;
};

}  // namespace ghidra