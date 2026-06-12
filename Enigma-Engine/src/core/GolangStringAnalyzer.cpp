#include <ghidra/GolangStringAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>
#include <vector>
#include <cctype>
#include <algorithm>

namespace ghidra {

static const char* MARKUP_SLICES_OPTIONNAME = "Markup slices";
static const char* MARKUP_SLICES_DESC = "Markup things that look like slices.";
static const char* MARKUP_STRUCTS_IN_DATA_OPTIONNAME = "Search data segments";
static const char* MARKUP_STRUCTS_IN_DATA_DESC =
    "Search for strings and slices in data segments.";

static uint32_t readU32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 0) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

static uint64_t readPtr(const uint8_t* buf, bool is64) {
    if (is64) {
        return (static_cast<uint64_t>(buf[0]) << 0) |
               (static_cast<uint64_t>(buf[1]) << 8) |
               (static_cast<uint64_t>(buf[2]) << 16) |
               (static_cast<uint64_t>(buf[3]) << 24) |
               (static_cast<uint64_t>(buf[4]) << 32) |
               (static_cast<uint64_t>(buf[5]) << 40) |
               (static_cast<uint64_t>(buf[6]) << 48) |
               (static_cast<uint64_t>(buf[7]) << 56);
    }
    return readU32(buf);
}

GolangStringAnalyzer::GolangStringAnalyzer()
    : AbstractAnalyzer("Golang Strings",
                       "Finds and labels Go string structures.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.after().after().after());
    setDefaultEnablement(true);
}

bool GolangStringAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    Language* lang = program->getLanguage();
    if (!lang) return false;
    std::string langId = lang->getLanguageID().toString();
    return langId.find("Golang") != std::string::npos || langId.find("golang") != std::string::npos;
}

void GolangStringAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(MARKUP_SLICES_OPTIONNAME, markupSliceStructsOption_, MARKUP_SLICES_DESC);
    options.registerBool(MARKUP_STRUCTS_IN_DATA_OPTIONNAME, markupDataSegmentStructsOption_,
                         MARKUP_STRUCTS_IN_DATA_DESC);
}

void GolangStringAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(MARKUP_SLICES_OPTIONNAME)) {
        markupSliceStructsOption_ = options.getBool(MARKUP_SLICES_OPTIONNAME);
    }
    if (options.hasOption(MARKUP_STRUCTS_IN_DATA_OPTIONNAME)) {
        markupDataSegmentStructsOption_ = options.getBool(MARKUP_STRUCTS_IN_DATA_OPTIONNAME);
    }
}

bool GolangStringAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    if (!memory || !symTable || !listing) return true;

    AddressSpace* defaultSpace = program->getLanguage()->getDefaultSpace();
    if (!defaultSpace) return true;

    bool is64 = (defaultSpace->getSize() == 64);
    int ptrSize = is64 ? 8 : 4;
    int structSize = ptrSize * 2;

    int totalStrings = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;

        std::string blockName = block->getName();
        if (!markupDataSegmentStructsOption_) {
            if (blockName.find(".data") == std::string::npos &&
                blockName.find("rodata") == std::string::npos &&
                blockName.find("noptrdata") == std::string::npos) {
                continue;
            }
        }

        Address blockStart = block->getStart();
        Address blockEnd = block->getEnd();
        int64_t blockSize = blockEnd.getOffset() - blockStart.getOffset() + 1;
        if (blockSize < structSize) continue;

        if (monitor) monitor->setMessage(getName() + ": Scanning " + blockName);

        std::vector<uint8_t> data(static_cast<size_t>(blockSize));
        if (memory->getBytes(blockStart, data.data(), static_cast<int>(blockSize))
            != static_cast<int>(blockSize)) continue;

        int step = is64 ? 8 : 4;
        for (int64_t off = 0; off + structSize <= static_cast<int64_t>(blockSize); off += step) {
            if (monitor && monitor->isCancelled()) break;
            if (monitor && off % 4096 == 0) monitor->setProgress(static_cast<int>(off));

            uint64_t dataPtr = readPtr(&data[static_cast<size_t>(off)], is64);
            uint64_t length = readPtr(&data[static_cast<size_t>(off + ptrSize)], is64);

            if (length == 0 || length > 4096) continue;
            if (dataPtr == 0) continue;

            Address dataAddr(defaultSpace, static_cast<int64_t>(dataPtr));
            if (!memory->getBlock(dataAddr)) continue;

            uint8_t strBuf[64];
            int checkLen = static_cast<int>(std::min(length, static_cast<uint64_t>(sizeof(strBuf))));
            if (memory->getBytes(dataAddr, strBuf, checkLen) != checkLen) continue;

            bool printable = true;
            int nullCount = 0;
            for (int i = 0; i < checkLen; ++i) {
                if (strBuf[i] == 0) ++nullCount;
                else if (!std::isprint(strBuf[i]) && !std::isspace(strBuf[i])) {
                    printable = false;
                    break;
                }
            }
            if (!printable || nullCount > 1) continue;

            Address structAddr = blockStart.add(off);
            if (!listing->isUndefined(structAddr)) continue;

            std::string labelName = "go_string_" + std::to_string(totalStrings);
            symTable->createLabel(structAddr, labelName, SourceType::ANALYSIS);

            listing->createData(dataAddr, &StringDataType::dataType(), static_cast<int>(length));
            ++totalStrings;
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(totalStrings) +
                            " Go string structures");
    }
    if (totalStrings > 0) {
        Msg::info(getName(), "Discovered " + std::to_string(totalStrings) + " Go string patterns");
    }

    return true;
}

} // namespace ghidra
