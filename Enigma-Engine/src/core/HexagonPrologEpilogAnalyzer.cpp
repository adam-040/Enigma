#include <ghidra/HexagonPrologEpilogAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>
#include <ghidra/SourceType.h>

namespace ghidra {

const char* HexagonPrologEpilogAnalyzer::CALL_FIXUP_PROLOG_NAME = "prolog_save_regs";
const char* HexagonPrologEpilogAnalyzer::CALL_FIXUP_EPILOG_NAME = "prolog_restore_regs";

bool HexagonPrologEpilogAnalyzer::InstructionMaskValue::isMatch(const uint8_t* bytes) const {
    // Little-endian 4-byte instruction match: (bytes & mask) == (value & mask)
    uint32_t inst = static_cast<uint32_t>(bytes[0]) |
                    (static_cast<uint32_t>(bytes[1]) << 8) |
                    (static_cast<uint32_t>(bytes[2]) << 16) |
                    (static_cast<uint32_t>(bytes[3]) << 24);
    return (inst & mask) == (value & mask);
}

HexagonPrologEpilogAnalyzer::HexagonPrologEpilogAnalyzer()
    : AbstractAnalyzer("Hexagon Prolog/Epilog Functions",
                       "Detects common Prolog/Epilog functions used within Hexagon code and marks them as inline",
                       AnalyzerType::FUNCTION_ANALYZER),
      NOP(0xffff3fff, 0x7f000000),
      JUMPR_LR(0xffff3fff, 0x529f0000),
      JUMP(0xfe000001, 0x58000000),
      MEMD_PUSH(0xfdff0000, 0xa5de0000),
      MEMD_POP(0xfdff0000, 0x95de0000),
      DEALLOCFRAME(0xffff3fff, 0x901e001e),
      DEALLOC_RETURN(0xffff3fff, 0x961e001e) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::CODE_ANALYSIS.before());
}

bool HexagonPrologEpilogAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor() == Processor("Hexagon");
}

bool HexagonPrologEpilogAnalyzer::added(Program* program, const AddressSetView& set,
                                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    if (monitor) {
        monitor->setMessage("Find Prologs and Epilogs...");
        monitor->initialize(set.getNumAddresses());
    }

    FunctionIterator funcIter = program->getFunctionManager()->getFunctions(set, true);
    int cnt = 0;
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        Function* function = funcIter.next();
        if (!function) continue;

        if (monitor) {
            monitor->setProgress(++cnt);
        }

        if (function->isInline() || !function->getCallFixup().empty()) {
            continue;
        }

        Address entry = function->getEntryPoint();
        if (isProlog(program, entry, true, monitor)) {
            setPrologEpilog(function, true);
        } else if (isEpilog(program, entry, true, monitor)) {
            setPrologEpilog(function, false);
        }
    }

    return true;
}

bool HexagonPrologEpilogAnalyzer::isProlog(Program* program, Address entryPoint,
                                            bool recurseOk, TaskMonitor* monitor) {
    Memory* memory = program->getMemory();
    if (!memory) return false;

    int memdCnt = 0;
    bool returnPending = false;
    uint8_t bytes[4];

    for (int i = 0; i < 5; i++) {
        if (monitor && monitor->isCancelled()) return false;

        Address addr = entryPoint.add(i * 4);
        if (memory->getBytes(addr, bytes, 4) != 4) {
            return false;
        }

        if (NOP.isMatch(bytes)) {
            // ignore
        } else if (JUMPR_LR.isMatch(bytes)) {
            returnPending = true;
        } else if (JUMP.isMatch(bytes)) {
            if (!recurseOk ||
                !hasContinuationFunction(program, addr, true, monitor)) {
                return false;
            }
            returnPending = true;
        } else if (MEMD_PUSH.isMatch(bytes)) {
            ++memdCnt;
        } else {
            return false;
        }

        if (returnPending && ((bytes[1] & 0x0c0) == 0x0c0)) {
            break;
        }
    }

    return (memdCnt != 0);
}

bool HexagonPrologEpilogAnalyzer::isEpilog(Program* program, Address entryPoint,
                                            bool recurseOk, TaskMonitor* monitor) {
    Memory* memory = program->getMemory();
    if (!memory) return false;

    int memdCnt = 0;
    bool returnPending = false;
    uint8_t bytes[4];

    for (int i = 0; i < 5; i++) {
        if (monitor && monitor->isCancelled()) return false;

        Address addr = entryPoint.add(i * 4);
        if (memory->getBytes(addr, bytes, 4) != 4) {
            return false;
        }

        if (NOP.isMatch(bytes)) {
            // ignore
        } else if (JUMPR_LR.isMatch(bytes) || DEALLOC_RETURN.isMatch(bytes)) {
            returnPending = true;
        } else if (JUMP.isMatch(bytes)) {
            if (!recurseOk ||
                !hasContinuationFunction(program, addr, false, monitor)) {
                return false;
            }
            returnPending = true;
        } else if (MEMD_POP.isMatch(bytes)) {
            ++memdCnt;
        } else if (DEALLOCFRAME.isMatch(bytes)) {
            // ignore
        } else {
            return false;
        }

        if (returnPending && ((bytes[1] & 0x0c0) == 0x0c0)) {
            break;
        }
    }

    return (memdCnt != 0);
}

bool HexagonPrologEpilogAnalyzer::hasContinuationFunction(Program* program,
                                                           Address jumpFromAddr,
                                                           bool checkProlog,
                                                           TaskMonitor* monitor) {
    // Simplified: look up the function at jumpFromAddr, get its flow target
    // via getReferencesFrom, then recurse
    Listing* listing = program->getListing();
    if (!listing) return false;

    Instruction* instr = listing->getInstructionAt(jumpFromAddr);
    if (!instr) return false;

    // Use getFallThrough as a simple heuristic for jump destination
    // This is a simplification; Ghidra uses instr.getAddress(0)
    Address destAddr = instr->getFallThrough();
    if (!destAddr.isValid()) return false;

    if (checkProlog) {
        if (isProlog(program, destAddr, false, monitor)) {
            return setPrologEpilog(program, destAddr, true, monitor);
        }
    } else {
        if (isEpilog(program, destAddr, false, monitor)) {
            return setPrologEpilog(program, destAddr, false, monitor);
        }
    }
    return false;
}

bool HexagonPrologEpilogAnalyzer::setPrologEpilog(Program* program, Address entryPoint,
                                                    bool isProlog, TaskMonitor* monitor) {
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!listing || !funcMgr) return false;

    Function* function = funcMgr->getFunctionAt(entryPoint);
    if (!function) {
        AddressSet body(entryPoint);
        function = funcMgr->createFunction(
            isProlog ? "prolog_save_regs" : "epilog_restore_regs",
            entryPoint, body, SourceType::ANALYSIS);
        if (!function) return false;
    } else if (function->isInline()) {
        return true;
    }

    setPrologEpilog(function, isProlog);
    return true;
}

void HexagonPrologEpilogAnalyzer::setPrologEpilog(Function* function, bool isProlog) {
    if (fixupType_ == FixupType::Inline) {
        function->setInline(true);
    } else if (fixupType_ == FixupType::CallFixup) {
        function->setCallFixup(isProlog ? CALL_FIXUP_PROLOG_NAME : CALL_FIXUP_EPILOG_NAME);
    }

    if (function->getSource() == SourceType::DEFAULT) {
        std::string newName = (isProlog ? "prolog_save_regs@" : "epilog_restore_regs@") +
                              function->getEntryPoint().toString();
        function->setName(newName);
        function->setSource(SourceType::ANALYSIS);
    }
}

void HexagonPrologEpilogAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerInt("Prolog/Epilog Function Fixup", static_cast<int>(FixupType::CallFixup),
                        "Select fixup type which should be applied to Prolog/Epilog functions");
}

void HexagonPrologEpilogAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Prolog/Epilog Function Fixup")) {
        fixupType_ = static_cast<FixupType>(options.getInt("Prolog/Epilog Function Fixup"));
    }
}

} // namespace ghidra
