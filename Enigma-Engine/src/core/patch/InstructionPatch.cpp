#include "ghidra/patch/InstructionPatch.h"
#include "ghidra/Assembler.h"
#include "ghidra/Memory.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/AddressFactory.h"
#include "ghidra/Address.h"
#include <sstream>
#include <iomanip>

namespace ghidra::patch {

static std::string hexAddr(uint64_t addr) {
    std::ostringstream oss;
    oss << std::hex << addr;
    return oss.str();
}

InstructionPatch::InstructionPatch(uint64_t address,
                                   std::string assemblyText,
                                   std::string patchName,
                                   std::string patchDescription)
    : InstructionPatch(address, std::move(assemblyText), 0,
                       std::move(patchName), std::move(patchDescription))
{
}

InstructionPatch::InstructionPatch(uint64_t address,
                                   std::string assemblyText,
                                   uint64_t originalSize,
                                   std::string patchName,
                                   std::string patchDescription)
    : address_(address)
    , assemblyText_(std::move(assemblyText))
    , originalSize_(originalSize)
    , name_(patchName.empty() ? ("Instruction patch @ 0x" + hexAddr(address)) : patchName)
    , description_(std::move(patchDescription))
{
    id_ = PatchId::create();

    auto result = Assembler::instance().assemble(assemblyText_, address);
    if (!result.success) {
        assembleError_ = result.error;
        assembled_ = false;
        return;
    }
    newSize_ = result.bytes.size();
    assembled_ = true;
    absoluteRefs_ = std::move(result.absoluteRefs);

    if (originalSize_ == 0) {
        patchedBytes_ = std::move(result.bytes);
        description_ += " [WARNING: No original size info — no NOP padding applied]";
        return;
    }

    if (newSize_ > originalSize_) {
        blocked_ = true;
        description_ += " [NEEDS TRAMPOLINE: Instruction too large for slot]";
        return;
    }

    patchedBytes_ = std::move(result.bytes);
    if (newSize_ < originalSize_) {
        sizeMismatch_ = true;
        Assembler::fillMultiByteNopGap(patchedBytes_, originalSize_ - newSize_);
        if (result.ripRelative) {
            description_ += " [WARNING: RIP-relative instruction NOP-padded — verify target offsets]";
        }
    }
}

bool InstructionPatch::apply(Memory& memory, ProgramDB& program) {
    if (!assembled_ || patchedBytes_.empty()) return false;

    auto* af = program.getAddressFactory();
    if (!af) return false;
    Address addr = af->oldGetAddressFromLong(address_);

    uint64_t slotSize = originalSize_ ? originalSize_ : patchedBytes_.size();
    originalBytes_.resize(slotSize);
    for (size_t i = 0; i < slotSize; ++i) {
        originalBytes_[i] = memory.getByte(addr.add(static_cast<int64_t>(i)));
    }

    return true;
}

bool InstructionPatch::revert(Memory& memory, ProgramDB& program) {
    (void)memory;
    (void)program;
    return true;
}

std::string InstructionPatch::previewText() const {
    std::ostringstream oss;
    oss << "0x" << std::hex << address_ << ": " << assemblyText_;
    if (blocked_) {
        oss << " [BLOCKED: " << assembleError_ << "]";
    } else if (assembled_) {
        oss << " -> ";
        for (auto b : patchedBytes_)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
        oss << "(" << std::dec << newSize_ << "/" << originalSize_ << " bytes)";
        if (sizeMismatch_) oss << " [NOP-padded]";
    } else {
        oss << " [ERROR: " << assembleError_ << "]";
    }
    return oss.str();
}

std::vector<uint64_t> InstructionPatch::affectedAddresses() const {
    std::vector<uint64_t> addrs;
    if (trampolineMode_) {
        // Include cave addresses
        for (uint64_t i = 0; i < caveBytes_.size(); ++i)
            addrs.push_back(caveAddress_ + i);
    }
    uint64_t slotSize = size();
    for (uint64_t i = 0; i < slotSize; ++i)
        addrs.push_back(address_ + i);
    return addrs;
}

uint64_t InstructionPatch::size() const {
    if (trampolineMode_) return consumedSize_;
    return originalSize_ ? originalSize_ : static_cast<uint64_t>(patchedBytes_.size());
}

std::vector<std::pair<uint64_t, std::vector<uint8_t>>> InstructionPatch::additionalWrites() const {
    if (!trampolineMode_ || caveBytes_.empty()) return {};
    // The original site gets the JMP stub (patchedBytes_), cave gets the new code
    return {{caveAddress_, caveBytes_}};
}

void InstructionPatch::setTrampoline(uint64_t caveAddr, std::vector<uint8_t> siteBytes,
                                     std::vector<uint8_t> cave, uint64_t consumed) {
    trampolineMode_ = true;
    caveAddress_ = caveAddr;
    patchedBytes_ = std::move(siteBytes);
    caveBytes_ = std::move(cave);
    consumedSize_ = consumed;
    sizeMismatch_ = false;
    blocked_ = false;
    assembled_ = true;
}

bool InstructionPatch::conflictsWith(const Patch& other) const {
    if (other.category() == PatchCategory::INSTRUCTION ||
        other.category() == PatchCategory::BYTE ||
        other.category() == PatchCategory::NOP_FILL) {
        uint64_t otherStart = other.baseAddress();
        uint64_t otherEnd = otherStart + other.size();
        uint64_t myStart = address_;
        uint64_t myEnd = address_ + size();
        return myStart < otherEnd && otherStart < myEnd;
    }
    return false;
}

std::string InstructionPatch::getTrampolineCaveAddressHex() const {
    if (!trampolineMode_) return "";
    std::ostringstream oss;
    oss << "0x" << std::hex << caveAddress_;
    return oss.str();
}

bool InstructionPatch::isJumpToCave(uint64_t address) const {
    if (!trampolineMode_) return false;
    return address >= address_ && address < address_ + consumedSize_;
}

std::vector<std::pair<uint64_t, uint64_t>> InstructionPatch::getRelocationEntries() const {
    std::vector<std::pair<uint64_t, uint64_t>> entries;
    if (absoluteRefs_.empty()) return entries;

    if (trampolineMode_) {
        // Cave bytes: absolute refs are at caveAddress_ + ref.offset
        for (const auto& ref : absoluteRefs_) {
            entries.push_back({caveAddress_ + ref.offset, ref.value});
        }
    } else {
        // Site bytes: absolute refs are at address_ + ref.offset
        for (const auto& ref : absoluteRefs_) {
            entries.push_back({address_ + ref.offset, ref.value});
        }
    }
    return entries;
}

} // namespace ghidra::patch
