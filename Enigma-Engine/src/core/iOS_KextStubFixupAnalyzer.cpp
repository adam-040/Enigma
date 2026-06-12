#include <ghidra/iOS_KextStubFixupAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

static bool isArmOrAarch64(Program* program) {
    if (!program || !program->getLanguage()) return false;
    std::string name = program->getLanguage()->getProcessor().getName();
    return name == "ARM" || name == "AARCH64";
}

// Detect ARM64 ADRP + ADD sequence used in kext stubs:
// ADRP x16, #page    -> 0x90000110 (example)
// ADD  x16, x16, #imm -> 0x91000210 (example)
// BR   x16           -> 0xD61F0200
static bool detectAarch64Stub(uint8_t* bytes, int64_t& target) {
    // Simple heuristic: look for ADRP + ADD/BR pattern
    uint32_t w0 = static_cast<uint32_t>(bytes[0]) |
                  (static_cast<uint32_t>(bytes[1]) << 8) |
                  (static_cast<uint32_t>(bytes[2]) << 16) |
                  (static_cast<uint32_t>(bytes[3]) << 24);
    uint32_t w1 = static_cast<uint32_t>(bytes[4]) |
                  (static_cast<uint32_t>(bytes[5]) << 8) |
                  (static_cast<uint32_t>(bytes[6]) << 16) |
                  (static_cast<uint32_t>(bytes[7]) << 24);

    // ADRP has op0=1, op1=10000 in bits 31-24
    if ((w0 & 0x9F000000) == 0x90000000) {
        // Could be ADRP + ADD (0x91000000) or ADRP + LDR (0xF9400000)
        if ((w1 & 0xFFC00000) == 0x91000000 || (w1 & 0xFFC00000) == 0xF9400000) {
            return true;
        }
    }
    return false;
}

iOS_KextStubFixupAnalyzer::iOS_KextStubFixupAnalyzer()
    : AbstractAnalyzer("iOS Kext Stub Fixup",
                       "Fixup stubs in iOS kernel extensions.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS);
    setDefaultEnablement(false);
}

bool iOS_KextStubFixupAnalyzer::canAnalyze(Program* program) const {
    return isArmOrAarch64(program);
}

bool iOS_KextStubFixupAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool iOS_KextStubFixupAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Fixing up iOS kext stubs...");

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    if (!memory || !listing || !symTable) return true;

    bool is64Bit = program->getLanguage()->getDefaultSpace()->getSize() >= 64;
    int stubsFixed = 0;

    // Scan for kext stubs in __TEXT_EXEC or __text sections
    for (auto* block : memory->getBlocks()) {
        if (monitor->isCancelled()) break;
        std::string name = block->getName();
        if (name.find("__TEXT_EXEC") == std::string::npos &&
            name.find("__text") == std::string::npos &&
            name.find("text") == std::string::npos) continue;

        Address addr = block->getStart();
        Address end = block->getEnd();

        while (addr <= end && !monitor->isCancelled()) {
            if (!listing->isUndefined(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            // Read a chunk to check for stub patterns
            uint8_t bytes[12] = {};
            MemoryBlock* blk = memory->getBlock(addr);
            if (!blk) { try { addr = addr.add(1); } catch (...) { break; } continue; }
            int read = blk->getBytes(addr, bytes, (is64Bit ? 12 : 8));
            if (read < (is64Bit ? 12 : 8)) { try { addr = addr.add(1); } catch (...) { break; } continue; }

            int64_t target = 0;
            if (is64Bit && detectAarch64Stub(bytes, target)) {
                // Mark as a potential stub
                AddressSet stubBody(addr, addr);
                Function* stub = program->getFunctionManager()->createFunction(
                    "kext_stub_" + std::to_string(addr.getOffset()),
                    addr, stubBody, SourceType::ANALYSIS);
                if (stub) {
                    ++stubsFixed;
                    try { addr = addr.add(8); } catch (...) { break; }
                    continue;
                }
            }

            try { addr = addr.add(1); } catch (...) { break; }
        }
    }

    if (stubsFixed > 0) {
        Msg::info(getName(), "Fixed up " + std::to_string(stubsFixed) + " kext stubs.");
    }
    return true;
}

} // namespace ghidra
