#include <ghidra/TEBAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <sstream>

namespace ghidra {

static const char* ADDRESS_OPTION_NAME = "Starting Address of the TEB";
static const char* ADDRESS_OPTION_DESCRIPTION =
    "Address in RAM where TEB is located (must not be mapped to another block)";
static const char* VERSION_OPTION_NAME = "Windows OS Version";
static const char* VERSION_OPTION_DESCRIPTION =
    "Version of the TEB fields to lay down.";
static const char* TEB_BLOCK_NAME = "_TEB";

TEBAnalyzer::TEBAnalyzer()
    : AbstractAnalyzer("Windows x86 Thread Environment Block (TEB) Analyzer",
                       "Create and mark up a Thread Environment Block. Set FS or GS segments to point to it.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after());
    setDefaultEnablement(true);
}

bool TEBAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    std::string langId = program->getLanguageID().getIdAsString();
    if (langId.find("x86") != 0) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

void TEBAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerString(ADDRESS_OPTION_NAME, "", ADDRESS_OPTION_DESCRIPTION);
    options.registerString(VERSION_OPTION_NAME, "WIN_7", VERSION_OPTION_DESCRIPTION);
}

void TEBAnalyzer::optionsChanged(Options& options, Program* program) {
    tebAddressString_ = options.getString(ADDRESS_OPTION_NAME);
    winVersion_ = options.getString(VERSION_OPTION_NAME);
}

Address TEBAnalyzer::findTEBAddress(Program* program, bool is64Bit, int blockSize) {
    uint64_t offset = is64Bit ? 0x7FF000000ULL : 0x7FFDF000ULL;
    AddressSpace* defaultSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());
    if (!defaultSpace) return Address();
    Address startAddr(defaultSpace, static_cast<int64_t>(offset));

    Address result = startAddr;
    for (auto* block : program->getMemory()->getBlocks()) {
        if (!block) continue;
        if (block->getStart().getAddressSpace() == defaultSpace) {
            Address blockEnd = block->getEnd();
            if (startAddr < blockEnd) {
                result = blockEnd.add(1);
            }
        }
    }
    return result;
}

bool TEBAnalyzer::added(Program* program, const AddressSetView& set,
                        TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing Thread Environment Block...");

    DefaultMemory* memory = dynamic_cast<DefaultMemory*>(program->getMemory());
    if (!memory) return false;

    // Check if TEB block already exists
    for (auto* block : memory->getBlocks()) {
        if (block && block->getName() == TEB_BLOCK_NAME) {
            return true;
        }
    }

    bool is64Bit = (program->getLanguageID().getIdAsString().find("64") != std::string::npos);
    int tebSize = is64Bit ? 0x1000 : 0x800;

    // Determine TEB address
    Address tebAddr;
    if (!tebAddressString_.empty()) {
        uint64_t offset;
        std::stringstream ss;
        ss << std::hex << tebAddressString_;
        ss >> offset;
        if (ss.fail()) offset = 0;

        if (offset == 0) {
            tebAddr = findTEBAddress(program, is64Bit, tebSize);
        } else {
            AddressSpace* defaultSpace = const_cast<AddressSpace*>(
                program->getAddressFactory()->getDefaultAddressSpace());
            if (!defaultSpace) return false;
            tebAddr = Address(defaultSpace, static_cast<int64_t>(offset));
        }
    } else {
        tebAddr = findTEBAddress(program, is64Bit, tebSize);
    }

    if (!tebAddr.isValid()) return false;

    // Create TEB memory block (zero-initialized)
    DefaultMemoryBlock* tebBlock = memory->createInitializedBlock(TEB_BLOCK_NAME, tebAddr,
                                                                    tebSize, 0, false);
    if (!tebBlock) {
        log.append("Failed to create TEB memory block at " + tebAddr.toString());
        return false;
    }

    // Set FS (32-bit) or GS (64-bit) segment register to point to TEB
    std::string segRegName = is64Bit ? "gs" : "fs";
    Register* segReg = program->getRegister(segRegName);
    if (segReg) {
        ProgramContext* progCtx = program->getProgramContext();
        if (progCtx) {
            int regSize = segReg->getBitLength() / 8;
            if (regSize <= 0) regSize = sizeof(uint64_t);
            RegisterValue* regVal = new RegisterValue(segReg,
                static_cast<uint64_t>(tebAddr.getOffset()), regSize);
            progCtx->setRegisterValue(regVal, program->getMinAddress(), program->getMaxAddress());
        }
    }

    if (monitor) {
        monitor->setMessage("Created TEB at " + tebAddr.toString());
    }

    return true;
}

} // namespace ghidra
