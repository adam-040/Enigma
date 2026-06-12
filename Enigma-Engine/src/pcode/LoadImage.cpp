#include <ghidra/LoadImage.h>
#include <algorithm>
#include <fstream>
#include <stdexcept>
#include <cstring>

namespace ghidra {

void LoadImageBindArray::addSection(const Address& baseAddr, const uint1* data, int4 size) {
    Section sec;
    sec.baseAddr = baseAddr;
    sec.size = size;
    sec.data.assign(data, data + size);
    sections.push_back(sec);
}

void LoadImageBindArray::loadFill(uint1* ptr, int4 size, const Address& addr) {
    std::memset(ptr, 0, size);
    for (const auto& sec : sections) {
        int64_t secStart = sec.baseAddr.getOffset();
        int64_t secEnd = secStart + sec.size;
        int64_t reqStart = addr.getOffset();

        if (reqStart >= secStart && reqStart < secEnd) {
            int4 offset = static_cast<int4>(reqStart - secStart);
            int4 copySize = std::min(size, static_cast<int4>(secEnd - reqStart));
            std::memcpy(ptr, &sec.data[offset], copySize);
            return;
        }
    }
}

void LoadImageBindArray::adjustVma(long adjust) {
    for (auto& sec : sections) {
        auto* space = sec.baseAddr.getAddressSpace();
        sec.baseAddr = Address(space, sec.baseAddr.getOffset() + adjust);
    }
}

void LoadImageBindArray::applyRelocations(uint1* img, int4 size, const Address& addr) {
    (void)img; (void)size; (void)addr;
}

LoadImageRawFile::LoadImageRawFile(const std::string& filename, const Address& base, const std::string& arch)
    : baseAddr(base), archType(arch) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    auto fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    fileData.resize(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(fileData.data()), fileSize);
}

void LoadImageRawFile::loadFill(uint1* ptr, int4 size, const Address& addr) {
    int64_t offset = addr.getOffset() - baseAddr.getOffset();
    std::memset(ptr, 0, size);
    if (offset < 0 || offset >= static_cast<int64_t>(fileData.size())) {
        return;
    }
    int4 available = static_cast<int4>(fileData.size() - offset);
    int4 copySize = std::min(size, available);
    if (copySize > 0) {
        std::memcpy(ptr, &fileData[static_cast<size_t>(offset)], copySize);
    }
}

void LoadImageRawFile::adjustVma(long adjust) {
    auto* space = baseAddr.getAddressSpace();
    baseAddr = Address(space, baseAddr.getOffset() + adjust);
}

void LoadImageRawFile::applyRelocations(uint1* img, int4 size, const Address& addr) {
    (void)img; (void)size; (void)addr;
}

} // namespace ghidra
