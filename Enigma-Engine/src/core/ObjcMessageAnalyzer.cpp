#include <ghidra/ObjcMessageAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <ghidra/Options.h>

#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
#include <algorithm>
#include <unordered_map>

namespace ghidra {

static const char* OPTION_NAME_CALL_OVERRIDE_REFS = "Use CALL_OVERRIDE_UNCONDITIONAL references";
static const char* OPTION_DESCRIPTION_CALL_OVERRIDE_REFS =
    "Applies CALL_OVERRIDE_UNCONDITIONAL references instead of UNCONDITIONAL_CALL "
    "references to _objc_msgSend calls. This makes the decompiler look nice.";

static const char* OPTION_NAME_LOG_MESSAGE_FAILURES = "Log message fix failures";
static const char* OPTION_DESCRIPTION_LOG_MESSAGE_FAILURES =
    "Log message fix failures during analysis (useful for debugging).";

static uint32_t readU32LE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 0) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t readU64LE(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]) << 0) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

ObjcMessageAnalyzer::ObjcMessageAnalyzer()
    : AbstractAnalyzer("Objective-C Message Analyzer",
                       "Analyzes _objc_msgSend information.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::DATA_ANALYSIS.before().before());
}

bool ObjcMessageAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    std::string processorName = program->getLanguage()->getProcessor().getName();
    if (processorName == "AARCH64" || processorName == "ARM") return true;
    std::string langId = program->getLanguageID().getIdAsString();
    if (langId.find("ARM") != std::string::npos || langId.find("AARCH64") != std::string::npos) return true;
    return false;
}

bool ObjcMessageAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    FunctionManager* funcMgr = program->getFunctionManager();
    AddressSpace* defaultSpace = program->getLanguage()->getDefaultSpace();
    if (!memory || !listing || !symTable || !funcMgr || !defaultSpace) return true;

    bool is64 = (defaultSpace->getSize() == 64);
    int ptrSize = is64 ? 8 : 4;

    // Find all objc_msgSend symbols
    std::vector<Symbol*> msgSendSyms;
    std::vector<std::string> msgSendNames = {
        "_objc_msgSend", "_objc_msgSendSuper",
        "_objc_msgSend_stret", "_objc_msgSendSuper_stret",
        "_objc_msgSend_fpret"
    };
    for (const auto& name : msgSendNames) {
        SymbolIterator it = symTable->getSymbols(name);
        while (it.hasNext()) {
            msgSendSyms.push_back(it.next());
        }
    }

    if (msgSendSyms.empty()) return true;

    // Build selector reference map: sel_ptr -> sel_name
    std::unordered_map<uint64_t, std::string> selRefMap;
    for (auto* block : memory->getBlocks()) {
        std::string blockName = block->getName();
        if (blockName.find("__objc_selrefs") == std::string::npos &&
            blockName.find("objc_selrefs") == std::string::npos) continue;

        Address blockStart = block->getStart();
        int64_t blockSize = block->getEnd().getOffset() - blockStart.getOffset() + 1;
        if (blockSize < static_cast<int64_t>(ptrSize)) continue;

        std::vector<uint8_t> data(static_cast<size_t>(blockSize));
        if (memory->getBytes(blockStart, data.data(), static_cast<int>(blockSize))
            != static_cast<int>(blockSize)) continue;

        int maxEntries = static_cast<int>(blockSize / ptrSize);
        for (int i = 0; i < maxEntries; ++i) {
            uint64_t selPtr;
            if (is64) {
                selPtr = readU64LE(&data[static_cast<size_t>(i * ptrSize)]);
            } else {
                selPtr = readU32LE(&data[static_cast<size_t>(i * ptrSize)]);
            }
            if (selPtr == 0) continue;

            Address selAddr(defaultSpace, static_cast<int64_t>(selPtr));
            if (!memory->getBlock(selAddr)) continue;

            uint8_t selBuf[128];
            int bytesRead = memory->getBytes(selAddr, selBuf, static_cast<int>(sizeof(selBuf) - 1));
            if (bytesRead <= 0) continue;

            std::string selName;
            bool validSel = true;
            for (int si = 0; si < bytesRead; ++si) {
                if (selBuf[si] == 0) break;
                unsigned char c = selBuf[si];
                if (!std::isprint(c)) { validSel = false; break; }
                selName += static_cast<char>(c);
            }
            if (validSel && !selName.empty()) {
                selRefMap[selPtr] = selName;
            }
        }
    }

    // Process functions containing objc_msgSend calls
    int totalCalls = 0;
    int totalResolved = 0;

    std::vector<Instruction*> instructions = listing->getInstructions(set);
    for (auto* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;
        if (!instr) continue;

        // Check if this is a CALL instruction
        FlowType* ft = instr->getFlowType();
        if (!ft || (!ft->isCall() && !ft->isComputed())) continue;

        // Get call destination
        const std::vector<Varnode*>& flows = instr->getFlows();
        if (flows.empty()) continue;

        Address destAddr = flows[0]->getAddress();

        bool isMsgSend = false;
        for (auto* msgSym : msgSendSyms) {
            if (msgSym && msgSym->getAddress() == destAddr) {
                isMsgSend = true;
                break;
            }
        }
        if (!isMsgSend) continue;

        ++totalCalls;
        Address callAddr = instr->getAddress();

        // For ARM64: x1 holds the selector pointer before calling objc_msgSend
        // Look backwards for LDR x1, [xN, #offset] that loads from selrefs
        std::string resolvedSel;
        Address prevAddr = callAddr;

        for (int back = 0; back < 24; ++back) {
            prevAddr = prevAddr.subtract(4);
            if (!memory->getBlock(prevAddr)) break;

            Instruction* prevInstr = listing->getInstructionAt(prevAddr);
            if (!prevInstr || prevInstr->getAddress() == callAddr) continue;

            // Get the Varnode operands
            // For ARM64 LDR encoding, check if destination is x1 and
            // the source address falls in __objc_selrefs
            uint8_t ibuf[8];
            int64_t remaining = memory->getBlock(prevAddr)->getEnd().getOffset() - prevAddr.getOffset() + 1;
            if (memory->getBytes(prevAddr, ibuf, static_cast<int>(std::min(static_cast<int64_t>(8), remaining))) < 4) continue;
            uint32_t encoding = readU32LE(ibuf);

            // ARM64 ADRP x1, #page : 0x90000010 | (page << 5)
            if ((encoding & 0x9F00001F) == 0x90000010) {
                // ADRP loads page address of the selector reference
                // The following LDR usually loads the selector pointer from that page
                int64_t immhi = static_cast<int64_t>((encoding >> 5) & 0x7FFFF) << 2;
                int64_t immlo = static_cast<int64_t>((encoding >> 29) & 0x3);
                int64_t pageOff = (immhi | immlo) << 12;
                int64_t pcPage = (prevAddr.getOffset() >> 12) << 12;
                uint64_t targetPage = static_cast<uint64_t>(pcPage + pageOff);

                // Look for a subsequent LDR x1, [xN, #imm] that follows the ADRP
                for (int fwd = 0; fwd < 3; ++fwd) {
                    Address ldrAddr = prevAddr.add(static_cast<int64_t>(4 * (fwd + 1)));
                    if (!memory->getBlock(ldrAddr)) break;
                    Instruction* ldrInstr = listing->getInstructionAt(ldrAddr);
                    if (!ldrInstr) continue;

                    uint8_t lbuf[8];
                    int64_t ldrRemaining = memory->getBlock(ldrAddr)->getEnd().getOffset() - ldrAddr.getOffset() + 1;
                    if (memory->getBytes(ldrAddr, lbuf, static_cast<int>(std::min(static_cast<int64_t>(8), ldrRemaining))) < 4) continue;
                    uint32_t ldrEnc = readU32LE(lbuf);

                    // LDR x1, [xN, #imm] : check for immediate offset variant
                    if ((ldrEnc & 0xFFC0001F) == 0xF9400010) {
                        // Register-based LDR x1
                        int64_t imm12 = static_cast<int64_t>((ldrEnc >> 10) & 0xFFF);
                        uint64_t targetAddr = targetPage + (imm12 * 8);

                        // Check if targetAddr falls in selrefs
                        auto it = selRefMap.find(targetAddr);
                        if (it != selRefMap.end()) {
                            resolvedSel = it->second;
                            break;
                        }
                    } else if ((ldrEnc & 0xFFC0001F) == 0xF9400010) {
                        // Alternative LDR pattern
                        (void)ldrEnc;
                    }
                }
                if (!resolvedSel.empty()) break;
            }

            // ARM32 LDR r1, [pc, #imm] pattern
            if ((encoding & 0x0E000000) == 0x04000000) {
                // LDR r1, [pc, #imm] or similar
                // Simpler: check if any operand address falls in selrefs
                for (int opIdx = 0; opIdx < prevInstr->getNumOperands(); ++opIdx) {
                    // Can't easily check operand values without more infrastructure
                }
            }
        }

        // If selector was resolved, add a comment
        if (!resolvedSel.empty()) {
            instr->setComment("objc_msgSend(" + resolvedSel + ")");
            ++totalResolved;
        } else if (logMessageFailures_) {
            Msg::debug(getName(), "Unresolved objc_msgSend call at " + callAddr.toString());
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Processed " + std::to_string(totalCalls) +
                            " objc_msgSend calls (" + std::to_string(totalResolved) + " resolved)");
    }

    if (totalCalls > 0) {
        log.append(getName(), "Analyzed " + std::to_string(totalCalls) +
                   " objc_msgSend calls, " + std::to_string(totalResolved) + " selectors resolved");
    }

    return true;
}

void ObjcMessageAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CALL_OVERRIDE_REFS, true,
                         OPTION_DESCRIPTION_CALL_OVERRIDE_REFS);
    options.registerBool(OPTION_NAME_LOG_MESSAGE_FAILURES, false,
                         OPTION_DESCRIPTION_LOG_MESSAGE_FAILURES);
}

void ObjcMessageAnalyzer::optionsChanged(Options& options, Program* program) {
    useCallOverrides_ = options.getBool(OPTION_NAME_CALL_OVERRIDE_REFS);
    logMessageFailures_ = options.getBool(OPTION_NAME_LOG_MESSAGE_FAILURES);
}

} // namespace ghidra
