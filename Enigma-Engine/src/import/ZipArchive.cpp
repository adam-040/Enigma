/* ###
 * IP: Enigma Engine (original work)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ZipArchive.h"

#include <cstring>
#include <fstream>
#include <stdexcept>
#include <zlib.h>

namespace ghidra {

namespace {

constexpr uint32_t kEocdSig = 0x06054b50;
constexpr uint32_t kCentralSig = 0x02014b50;
constexpr uint32_t kLocalSig = 0x04034b50;

uint16_t rdU16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t rdU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

}  // namespace

ZipArchive::ZipArchive(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {
    // Locate EOCD: scan backwards from the end over up to 64K + 22 bytes.
    if (bytes_.size() < 22) {
        throw std::runtime_error("Zip: file too small");
    }
    size_t searchStart = bytes_.size() > 65557 ? bytes_.size() - 65557 : 0;
    int64_t eocd = -1;
    for (size_t i = bytes_.size() - 22 + 1; i-- > searchStart;) {
        if (rdU32(&bytes_[i]) == kEocdSig) {
            eocd = static_cast<int64_t>(i);
            break;
        }
    }
    if (eocd < 0) {
        throw std::runtime_error("Zip: end-of-central-directory not found");
    }
    const uint8_t* e = &bytes_[static_cast<size_t>(eocd)];
    uint16_t totalEntries = rdU16(e + 10);
    uint32_t cdSize = rdU32(e + 12);
    uint32_t cdOffset = rdU32(e + 16);

    if (cdOffset + cdSize > bytes_.size()) {
        throw std::runtime_error("Zip: bad central directory offset");
    }

    uint32_t pos = cdOffset;
    for (uint16_t i = 0; i < totalEntries; i++) {
        if (pos + 46 > bytes_.size() || rdU32(&bytes_[pos]) != kCentralSig) {
            throw std::runtime_error("Zip: bad central directory entry");
        }
        const uint8_t* c = &bytes_[pos];
        Entry entry;
        entry.flags = rdU16(c + 8);
        entry.method = rdU16(c + 10);
        entry.compSize = rdU32(c + 20);
        entry.uncompSize = rdU32(c + 24);
        uint16_t nameLen = rdU16(c + 28);
        uint16_t extraLen = rdU16(c + 30);
        uint16_t commentLen = rdU16(c + 32);
        entry.localOffset = rdU32(c + 42);
        if (pos + 46 + nameLen > bytes_.size()) {
            throw std::runtime_error("Zip: central directory entry truncated");
        }
        std::string name(reinterpret_cast<const char*>(c + 46), nameLen);
        entry.isDirectory = !name.empty() && name.back() == '/';
        entries_[name] = entry;
        names_.push_back(std::move(name));
        pos += 46u + nameLen + extraLen + commentLen;
    }
}

std::unique_ptr<ZipArchive> ZipArchive::fromFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) {
        throw std::runtime_error("Zip: cannot open file: " + path);
    }
    std::streamsize n = in.tellg();
    if (n <= 0) {
        throw std::runtime_error("Zip: empty file: " + path);
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(n));
    in.seekg(0);
    in.read(reinterpret_cast<char*>(bytes.data()), n);
    if (!in) {
        throw std::runtime_error("Zip: failed to read file: " + path);
    }
    return std::unique_ptr<ZipArchive>(new ZipArchive(std::move(bytes)));
}

const std::vector<std::string>& ZipArchive::entryNames() const {
    return names_;
}

bool ZipArchive::hasEntry(const std::string& name) const {
    return find(name) != nullptr;
}

const ZipArchive::Entry* ZipArchive::find(const std::string& name) const {
    auto it = entries_.find(name);
    return it == entries_.end() ? nullptr : &it->second;
}

std::vector<uint8_t> ZipArchive::readEntry(const std::string& name) const {
    const Entry* entry = find(name);
    if (entry == nullptr) {
        throw std::runtime_error("Zip: member not found: " + name);
    }
    if (entry->isDirectory) {
        return {};
    }
    if (entry->method != 0 && entry->method != 8) {
        throw std::runtime_error("Zip: unsupported compression method " +
            std::to_string(entry->method) + " for " + name);
    }

    // Locate the data through the local file header.
    if (entry->localOffset + 30 > bytes_.size()) {
        throw std::runtime_error("Zip: bad local header offset for " + name);
    }
    const uint8_t* l = &bytes_[entry->localOffset];
    if (rdU32(l) != kLocalSig) {
        throw std::runtime_error("Zip: missing local header for " + name);
    }
    uint16_t nameLen = rdU16(l + 26);
    uint16_t extraLen = rdU16(l + 28);
    size_t dataOff = entry->localOffset + 30u + nameLen + extraLen;
    if (dataOff + entry->compSize > bytes_.size()) {
        throw std::runtime_error("Zip: compressed data out of range for " + name);
    }
    const uint8_t* comp = &bytes_[dataOff];

    if (entry->method == 0) {
        return std::vector<uint8_t>(comp, comp + entry->compSize);
    }

    // Deflate (raw, no zlib wrapper).
    std::vector<uint8_t> out(entry->uncompSize);
    if (out.empty()) {
        return out;
    }
    z_stream strm;
    std::memset(&strm, 0, sizeof(strm));
    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK) {
        throw std::runtime_error("Zip: inflateInit failed for " + name);
    }
    strm.next_in = const_cast<Bytef*>(comp);
    strm.avail_in = entry->compSize;
    strm.next_out = out.data();
    strm.avail_out = static_cast<uInt>(out.size());
    int rc = inflate(&strm, Z_FINISH);
    inflateEnd(&strm);
    if (rc != Z_STREAM_END) {
        throw std::runtime_error("Zip: inflate failed for " + name);
    }
    return out;
}

}  // namespace ghidra