#include "ghidra/patch/StringPatch.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace ghidra::patch {

static std::vector<uint8_t> stringToBytes(const std::string& str, StringPatch::Encoding enc) {
    std::vector<uint8_t> bytes;
    switch (enc) {
    case StringPatch::Encoding::ASCII:
    case StringPatch::Encoding::UTF8:
        bytes.assign(str.begin(), str.end());
        bytes.push_back(0);
        break;
    case StringPatch::Encoding::UTF16:
        for (size_t i = 0; i < str.size(); ++i) {
            uint16_t ch = static_cast<uint16_t>(static_cast<unsigned char>(str[i]));
            bytes.push_back(static_cast<uint8_t>(ch & 0xFF));
            bytes.push_back(static_cast<uint8_t>((ch >> 8) & 0xFF));
        }
        bytes.push_back(0);
        bytes.push_back(0);
        break;
    }
    return bytes;
}

StringPatch::StringPatch(uint64_t address,
                         const std::string& original,
                         const std::string& patched,
                         Encoding encoding,
                         std::string patchName,
                         std::string patchDescription)
    : BytePatch(
        address,
        stringToBytes(original, encoding),
        stringToBytes(patched, encoding),
        "",
        std::move(patchDescription))
    , originalStr_(original)
    , patchedStr_(patched)
    , encoding_(encoding)
{
    if (patchName.empty()) {
        std::ostringstream oss;
        const char* encStr = (encoding == Encoding::UTF16) ? "UTF-16" :
                             (encoding == Encoding::UTF8)  ? "UTF-8" : "ASCII";
        oss << "Edit " << encStr << " string @ 0x" << std::hex << address;
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

} // namespace ghidra::patch
