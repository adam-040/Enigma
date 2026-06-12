#include <ghidra/iOS_Analyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <memory>
#include <string>

namespace ghidra {

static bool isIosBoot(Program* program) {
    if (!program || !program->getLanguage() || !program->getMemory()) return false;
    if (program->getLanguage()->getProcessor().getName() != "ARM") return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    Address addr = minAddr.add(0x200);
    if (!addr.isValid()) return false;
    uint8_t bytes[0x40] = {0};
    if (program->getMemory()->getBytes(addr, bytes, 0x40) != 0x40) return false;
    std::string s(reinterpret_cast<char*>(bytes), 0x40);
    size_t pos = s.find("Apple");
    if (pos == std::string::npos) return false;
    return s.find("SecureROM") == 0 || s.find("LLB") == 0 ||
           s.find("iBoot") == 0 || s.find("iBEC") == 0 || s.find("iBSS") == 0;
}

iOS_Analyzer::iOS_Analyzer()
    : AbstractAnalyzer("iOS iBoot/LLB/iBSS/iBEC Analyzer",
                       "Disassembles iBoot/LLB/iBSS/iBEC ARM binaries.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(false);
}

bool iOS_Analyzer::canAnalyze(Program* program) const {
    return isIosBoot(program);
}

bool iOS_Analyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool iOS_Analyzer::added(Program* program, const AddressSetView& set,
                          TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing iOS boot binary...");

    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    auto* dtm = program->getDataTypeManager();
    auto* symTable = program->getSymbolTable();
    if (!memory || !listing || !dtm || !symTable) return false;

    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;

    // Detect boot type from string at offset 0x200
    Address bootStrAddr = minAddr.add(0x200);
    if (!bootStrAddr.isValid()) return false;

    uint8_t bootTypeBuf[0x40] = {0};
    if (memory->getBytes(bootStrAddr, bootTypeBuf, 0x40) != 0x40) return false;
    std::string bootType(reinterpret_cast<char*>(bootTypeBuf), 0x40);
    size_t nullPos = bootType.find('\0');
    if (nullPos != std::string::npos) bootType = bootType.substr(0, nullPos);
    size_t applePos = bootType.find("Apple");
    if (applePos != std::string::npos) {
        bootType = bootType.substr(0, applePos);
    }
    size_t trimPos = bootType.find_last_not_of(" \t\r\n");
    if (trimPos != std::string::npos) bootType = bootType.substr(0, trimPos + 1);

    // Create boot strings struct at 0x200
    auto bootStrStruct = std::make_unique<StructureDataType>("iOS_Boot_Strings", 0, dtm);
    bootStrStruct->add(new ArrayDataType(&ByteDataType::dataType(), 0x40, 1, dtm), 0x40, "boot_strings", "");
    DataType* resolvedBootStr = dtm->resolve(bootStrStruct.get(), nullptr);
    if (resolvedBootStr) {
        Data* strData = listing->createData(bootStrAddr, resolvedBootStr);
        if (strData) {
            strData->setComment("iOS Boot Type: " + bootType);
        }
    }
    symTable->createLabel(bootStrAddr, "BOOT_STRINGS", SourceType::ANALYSIS);

    if (!bootType.empty()) {
        symTable->createLabel(bootStrAddr, bootType, SourceType::ANALYSIS);
    }

    if (monitor) monitor->setMessage("iOS boot binary analysis complete: " + bootType);
    return true;
}

} // namespace ghidra
