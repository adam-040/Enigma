#include "ghidra/patch/NopFillPatch.h"
#include <sstream>
#include <iomanip>

namespace ghidra::patch {

NopFillPatch::NopFillPatch(uint64_t address, uint64_t fillSize,
                           uint8_t fillByte,
                           std::string patchName,
                           std::string patchDescription)
    : BytePatch(
        address,
        std::vector<uint8_t>(fillSize, 0),
        std::vector<uint8_t>(fillSize, fillByte),
        "",
        std::move(patchDescription))
{
    if (patchName.empty()) {
        std::ostringstream oss;
        if (fillByte == 0x90) {
            oss << "NOP fill @ 0x" << std::hex << address << " (" << std::dec << fillSize << " bytes)";
        } else {
            oss << "Fill @ 0x" << std::hex << address << " with 0x"
                << std::hex << std::setfill('0') << std::setw(2)
                << static_cast<int>(fillByte) << " (" << std::dec << fillSize << " bytes)";
        }
        name_ = oss.str();
    } else {
        name_ = std::move(patchName);
    }
}

} // namespace ghidra::patch
