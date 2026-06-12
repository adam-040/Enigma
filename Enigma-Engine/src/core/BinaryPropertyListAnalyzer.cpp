#include <ghidra/BinaryPropertyListAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <cstring>
#include <memory>

namespace ghidra {

namespace {
    Address findBplistBlock(Program* program) {
        if (!program || !program->getMemory()) return Address();
        for (MemoryBlock* block : program->getMemory()->getBlocks()) {
            Address start = block->getStart();
            if (!start.isValid()) continue;
            uint8_t buf[6] = {0};
            if (program->getMemory()->getBytes(start, buf, 6) != 6) continue;
            static const uint8_t magic[6] = { 'b', 'p', 'l', 'i', 's', 't' };
            if (std::memcmp(buf, magic, 6) == 0) return start;
        }
        return Address();
    }
}

BinaryPropertyListAnalyzer::BinaryPropertyListAnalyzer()
    : AbstractAnalyzer("Binary Property List (BPLIST) Annotation",
                       "Annotates a Binary Property List (BPLIST) file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool BinaryPropertyListAnalyzer::canAnalyze(Program* program) const {
    return findBplistBlock(program).isValid();
}

bool BinaryPropertyListAnalyzer::getDefaultEnablement(Program* program) const {
    return false; // disabled by default
}

bool BinaryPropertyListAnalyzer::added(Program* program, const AddressSetView& set,
                                       TaskMonitor* monitor, MessageLog& log) {
    Address plistAddress = findBplistBlock(program);
    if (!plistAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), plistAddress, program);
    BinaryReader reader(std::move(provider), true); // bplist is big-endian

    // Validate magic
    std::string magic = reader.readAsciiString(0, 6);
    if (magic != "bplist") {
        log.append("Invalid binary plist: bad magic");
        return false;
    }

    // Create header struct: magic(6) + majorVersion(1) + minorVersion(1) = 8 bytes
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("bplist", 0, dtm);
    headerType->add(&ByteDataType::dataType(), 6, "magic", nullptr);
    headerType->add(&ByteDataType::dataType(), 1, "majorVersion", nullptr);
    headerType->add(&ByteDataType::dataType(), 1, "minorVersion", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve binary plist header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(plistAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create binary plist header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated binary plist at " + plistAddress.toString());
    }

    return true;
}

} // namespace ghidra
