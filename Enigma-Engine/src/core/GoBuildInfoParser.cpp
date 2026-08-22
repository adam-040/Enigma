#include <ghidra/GoBuildInfoParser.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <cstring>

namespace ghidra {

static bool readString(const uint8_t* data, int64_t offset, int64_t maxLen, std::string& out) {
    if (offset < 0 || offset >= maxLen) return false;
    out.clear();
    for (int64_t i = offset; i < maxLen; ++i) {
        char c = static_cast<char>(data[i]);
        if (c == '\0') break;
        out += c;
    }
    return !out.empty();
}

GoBuildInfoParser::BuildInfo GoBuildInfoParser::parse(
    Memory* memory, const Address& start, int64_t size) {
    BuildInfo info;
    if (!memory || size < 32) return info;

    std::vector<uint8_t> data(static_cast<size_t>(size));
    int got = memory->getBytes(start, data.data(), static_cast<int>(size));
    if (got != static_cast<int>(size)) return info;

    // Look for "\xff Go buildinf:" magic header
    static const uint8_t MAGIC[] = {0xFF, ' ', 'G', 'o', ' ', 'b', 'u', 'i', 'l', 'd', 'i', 'n', 'f', ':'};
    static const int MAGIC_LEN = 14;

    int64_t magicOff = -1;
    for (int64_t i = 0; i + MAGIC_LEN <= size; ++i) {
        if (memcmp(&data[i], MAGIC, MAGIC_LEN) == 0) {
            magicOff = i;
            break;
        }
    }
    if (magicOff < 0) return info;

    // After magic: 2 byte pad, then pointers to goVersion, modPath, etc.
    int64_t ptrSize = 8; // assume 64-bit
    int64_t fieldsOff = magicOff + MAGIC_LEN + 2; // skip magic + 2 pad bytes

    // Read pointer-sized fields: goVersion, modPath, goCommandPath
    // Layout varies by Go version; try reading strings from pointer targets
    // For simplicity, scan the remaining data for readable strings

    // Find goVersion: typically first pointer after magic
    if (fieldsOff + ptrSize * 3 > size) return info;

    // Read the three pointers (goVersion, modPath, goCommandPath)
    uint64_t goVersionPtr = 0, modPathPtr = 0, goCommandPathPtr = 0;
    if (ptrSize == 8) {
        goVersionPtr = *reinterpret_cast<const uint64_t*>(&data[fieldsOff]);
        modPathPtr = *reinterpret_cast<const uint64_t*>(&data[fieldsOff + 8]);
        goCommandPathPtr = *reinterpret_cast<const uint64_t*>(&data[fieldsOff + 16]);
    } else {
        goVersionPtr = *reinterpret_cast<const uint32_t*>(&data[fieldsOff]);
        modPathPtr = *reinterpret_cast<const uint32_t*>(&data[fieldsOff + 4]);
        goCommandPathPtr = *reinterpret_cast<const uint32_t*>(&data[fieldsOff + 8]);
    }

    // Try to read strings at the pointer offsets relative to section start
    auto tryReadString = [&](uint64_t ptr, std::string& out) -> bool {
        // ptr is a virtual address; convert to file offset by subtracting section VMA
        uint64_t sectionVMA = start.getOffset();
        if (ptr < sectionVMA || ptr >= sectionVMA + static_cast<uint64_t>(size)) {
            // Try reading directly as an offset into the data
            if (ptr < static_cast<uint64_t>(size)) {
                return readString(data.data(), static_cast<int64_t>(ptr), size, out);
            }
            return false;
        }
        int64_t off = static_cast<int64_t>(ptr - sectionVMA);
        return readString(data.data(), off, size, out);
    };

    tryReadString(goVersionPtr, info.goVersion);
    tryReadString(modPathPtr, info.modulePath);

    // Also scan for embedded null-terminated strings that look like Go version
    for (int64_t i = 0; i + 4 < size; ++i) {
        if (data[i] == 'g' && data[i+1] == 'o' && data[i+2] == '1' && data[i+3] == '.') {
            std::string ver;
            if (readString(data.data(), i, size, ver) && ver.size() >= 5 && ver.size() <= 20) {
                if (info.goVersion.empty()) info.goVersion = ver;
                break;
            }
        }
    }

    info.valid = !info.goVersion.empty() || !info.modulePath.empty();
    return info;
}

GoBuildInfoParser::BuildInfo GoBuildInfoParser::findAndParse(Memory* memory) {
    BuildInfo info;
    if (!memory) return info;

    for (auto* block : memory->getBlocks()) {
        std::string name = block->getName();
        if (name.find("go.buildinfo") == std::string::npos &&
            name.find("go_buildinfo") == std::string::npos &&
            name.find("buildinfo") == std::string::npos) {
            continue;
        }

        Address start = block->getStart();
        int64_t size = block->getEnd().getOffset() - start.getOffset() + 1;
        info = parse(memory, start, size);
        if (info.valid) return info;
    }
    return info;
}

} // namespace ghidra
