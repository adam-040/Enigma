#include <ghidra/AggressiveInstructionFinderAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Language.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>

#include <string>
#include <vector>
#include <cstdint>
#include <cctype>
#include <algorithm>

namespace ghidra {

static const int MINIMUM_FUNCTION_COUNT = 20;

static const char* OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
static const char* OPTION_DESCRIPTION_CREATE_BOOKMARKS =
    "If checked, an analysis bookmark will be created at the start of each disassembly "
    "location where a run of instructions are identified by this analyzer.";
static const bool OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = true;

static std::string languageToArch(const std::string& langId) {
    std::string lower = langId;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("x86") != std::string::npos || lower.find("i386") != std::string::npos)
        return "x86";
    if (lower.find("arm") != std::string::npos)
        return "ARM";
    if (lower.find("mips") != std::string::npos)
        return "MIPS";
    if (lower.find("ppc") != std::string::npos || lower.find("powerpc") != std::string::npos)
        return "PowerPC";
    return "x86";
}

AggressiveInstructionFinderAnalyzer::AggressiveInstructionFinderAnalyzer()
    : AbstractAnalyzer(
          "Aggressive Instruction Finder",
          "Finds valid code in undefined bytes that have not been disassembled.\n"
          "WARNING: This should not be run unless good code has already been found.\n"
          "YOU MUST CHECK THE RESULTS, IT MAY CREATE A LOT OF BAD CODE!",
          AnalyzerType::BYTE_ANALYZER) {
    setPrototype(true);
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after());
    setDefaultEnablement(false);
}

bool AggressiveInstructionFinderAnalyzer::added(Program* program, const AddressSetView& set,
                                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    int funcCount = program->getFunctionManager()->getFunctionCount();
    if (funcCount < MINIMUM_FUNCTION_COUNT) {
        log.append("AggressiveInstructionFinder",
                   "Aggressive Instruction Finder Not Run.  "
                   "Too few functions defined for proper analysis!");
        return true;
    }

    if (monitor) monitor->setMessage("Aggressive Instruction Finder");

    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!programDB) return true;

    Language* lang = program->getLanguage();
    if (!lang) return true;

    LanguageID langId = lang->getLanguageID();
    std::string arch = languageToArch(langId.getIdAsString());
    int bitness = lang->getDefaultSpace()->getSize();
    bool bigEndian = lang->isBigEndian();

    auto disassembler = createDisassembler(arch, bitness, bigEndian);
    if (!disassembler) return true;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    BookmarkManager* bmMgr = program->getBookmarkManager();
    if (!memory || !listing) return true;

    int totalDiscovered = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;

        if (!block->isExecute()) continue;

        Address blockStart = block->getStart();
        Address blockEnd = block->getEnd();
        int64_t blockSize = blockEnd.getOffset() - blockStart.getOffset() + 1;
        if (blockSize <= 0) continue;

        if (monitor) {
            monitor->setMessage(getName() + ": Scanning " + block->getName());
        }

        int64_t addrOffset = 0;
        while (addrOffset < blockSize) {
            if (monitor && monitor->isCancelled()) break;

            Address currentAddr = blockStart.add(addrOffset);

            if (listing->isUndefined(currentAddr)) {
                int64_t remaining = blockSize - addrOffset;
                int checkSize = static_cast<int>(std::min(remaining, static_cast<int64_t>(256)));

                std::vector<uint8_t> bytes(checkSize);
                if (memory->getBytes(currentAddr, bytes.data(), checkSize) != checkSize) {
                    addrOffset += 1;
                    continue;
                }

                auto instructions = disassembler->disassembleRange(bytes, currentAddr.getOffset(),
                                                                    checkSize, 16);

                if (!instructions.empty()) {
                    int offset = 0;
                    for (const auto& di : instructions) {
                        if (monitor && monitor->isCancelled()) break;

                        Address addr = currentAddr.add(offset);
                        auto* inst = new Instruction(programDB, addr, di.mnemonic,
                                                      di.length, di.flowType);
                        for (const auto& op : di.operands) {
                            inst->setOperand(static_cast<int>(inst->getNumOperands()), op);
                        }
                        listing->addInstruction(inst);
                        offset += di.length;
                        ++totalDiscovered;
                    }

                    if (createBookmarksEnabled_ && bmMgr) {
                        bmMgr->setBookmark(currentAddr, "Analysis",
                                           "Discovered " + std::to_string(instructions.size()) +
                                           " instructions");
                    }

                    addrOffset += offset;
                } else {
                    addrOffset += 1;
                }
            } else {
                addrOffset += 1;
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Discovered " + std::to_string(totalDiscovered) +
                            " instructions in undefined regions");
    }

    return true;
}

void AggressiveInstructionFinderAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_BOOKMARKS,
                         OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED,
                         OPTION_DESCRIPTION_CREATE_BOOKMARKS);
}

void AggressiveInstructionFinderAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(OPTION_NAME_CREATE_BOOKMARKS)) {
        createBookmarksEnabled_ = options.getBool(OPTION_NAME_CREATE_BOOKMARKS);
    }
}

} // namespace ghidra
