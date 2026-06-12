#include <ghidra/GccExceptionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>
#include <vector>
#include <algorithm>

namespace ghidra {

static const char* OPTION_NAME_CREATE_TRY_CATCHS = "Create Try Catch Comments";
static const char* OPTION_DESCRIPTION_CREATE_TRY_CATCHS =
    "Selecting this check box causes the analyzer to create comments in the "
    "disassembly listing for the try and catch code.";

static uint32_t read32(const uint8_t* buf, int off) {
    return (static_cast<uint32_t>(buf[off]) << 0) |
           (static_cast<uint32_t>(buf[off + 1]) << 8) |
           (static_cast<uint32_t>(buf[off + 2]) << 16) |
           (static_cast<uint32_t>(buf[off + 3]) << 24);
}

GccExceptionAnalyzer::GccExceptionAnalyzer()
    : AbstractAnalyzer("GCC Exception Handlers",
                       "Locates and annotates exception-handling infrastructure installed by the GCC compiler",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after());
}

bool GccExceptionAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;

    CompilerSpec* compilerSpec = program->getCompilerSpec();
    if (!compilerSpec) return false;

    std::string id = compilerSpec->getCompilerSpecID().getIdAsString();
    std::transform(id.begin(), id.end(), id.begin(), ::tolower);

    if (id != "gcc" && id != "default") {
        return false;
    }

    Memory* memory = program->getMemory();
    if (!memory) return false;

    bool hasEHFrameHeader = memory->getBlock(".eh_frame_hdr") != nullptr;
    bool hasEHFrame = memory->getBlock(".eh_frame") != nullptr;
    bool hasDebugFrame = false;
    for (auto* block : memory->getBlocks()) {
        std::string name = block->getName();
        if (name.find(".debug_frame") == 0) {
            hasDebugFrame = true;
            break;
        }
    }

    return hasEHFrame || hasEHFrameHeader || hasDebugFrame;
}

void GccExceptionAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_TRY_CATCHS, createTryCatchCommentsEnabled_,
                         OPTION_DESCRIPTION_CREATE_TRY_CATCHS);
}

void GccExceptionAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(OPTION_NAME_CREATE_TRY_CATCHS)) {
        createTryCatchCommentsEnabled_ = options.getBool(OPTION_NAME_CREATE_TRY_CATCHS);
    }
}

bool GccExceptionAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    if (visitedPrograms_.find(program) != visitedPrograms_.end()) {
        return true;
    }
    visitedPrograms_.insert(program);

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !symTable) return true;

    MemoryBlock* ehFrameBlock = memory->getBlock(".eh_frame");
    if (!ehFrameBlock) return true;

    Address ehFrameStart = ehFrameBlock->getStart();
    Address ehFrameEnd = ehFrameBlock->getEnd();
    int64_t ehFrameSize = ehFrameEnd.getOffset() - ehFrameStart.getOffset() + 1;

    if (ehFrameSize < 8) return true;

    if (monitor) {
        monitor->setMessage(getName() + ": Parsing .eh_frame (" +
                            std::to_string(ehFrameSize) + " bytes)");
        monitor->initialize(static_cast<int>(ehFrameSize));
    }

    std::vector<uint8_t> ehData(static_cast<size_t>(ehFrameSize));
    if (memory->getBytes(ehFrameStart, ehData.data(), static_cast<int>(ehFrameSize))
        != static_cast<int>(ehFrameSize)) {
        return true;
    }

    int offset = 0;
    int cieCount = 0;
    int fdeCount = 0;

    while (offset + 8 <= static_cast<int>(ehFrameSize)) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(offset);

        uint32_t length = read32(ehData.data(), offset);
        int entrySize;

        if (length == 0) {
            // Zero terminator
            break;
        }

        if (length == 0xFFFFFFFF) {
            if (offset + 12 > static_cast<int>(ehFrameSize)) break;
            uint64_t length64 =
                (static_cast<uint64_t>(ehData[offset + 4]) << 0) |
                (static_cast<uint64_t>(ehData[offset + 5]) << 8) |
                (static_cast<uint64_t>(ehData[offset + 6]) << 16) |
                (static_cast<uint64_t>(ehData[offset + 7]) << 24) |
                (static_cast<uint64_t>(ehData[offset + 8]) << 32) |
                (static_cast<uint64_t>(ehData[offset + 9]) << 40) |
                (static_cast<uint64_t>(ehData[offset + 10]) << 48) |
                (static_cast<uint64_t>(ehData[offset + 11]) << 56);
            entrySize = static_cast<int>(length64 + 12);
        } else {
            entrySize = static_cast<int>(length + 4);
        }

        if (entrySize <= 0 || offset + entrySize > static_cast<int>(ehFrameSize)) break;

        int idOffset = offset + 4;
        uint32_t id = read32(ehData.data(), idOffset);
        bool isCIE = (id == 0);

        Address entryAddr = ehFrameStart.add(offset);

        if (isCIE) {
            std::string label = "CIE_" + std::to_string(cieCount);
            symTable->createLabel(entryAddr, label, SourceType::ANALYSIS);
            ++cieCount;
        } else {
            int offsetAfterID = offset + 8;
            if (offsetAfterID + 8 > static_cast<int>(ehFrameSize)) break;

            uint32_t initLoc = read32(ehData.data(), offsetAfterID);
            uint32_t rangeLen = read32(ehData.data(), offsetAfterID + 4);

            Address funcAddr = program->getImageBase().add(initLoc);

            std::string label = "FDE_" + std::to_string(fdeCount) + "_0x" + funcAddr.toString();
            symTable->createLabel(funcAddr, label, SourceType::ANALYSIS);

            if (refMgr) {
                refMgr->addMemoryReference(entryAddr, funcAddr, &RefTypes::DATA,
                                            SourceType::ANALYSIS, 0);
            }

            if (createTryCatchCommentsEnabled_) {
                Msg::info(getName(), "FDE at " + entryAddr.toString() +
                          " -> function at " + funcAddr.toString());
            }

            ++fdeCount;
        }

        offset += entrySize;
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(cieCount) +
                            " CIEs, " + std::to_string(fdeCount) + " FDEs");
    }

    return true;
}

} // namespace ghidra
