#include <ghidra/ArtAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/Language.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <cstring>
#include <memory>

namespace ghidra {

namespace {
    Address findArtBlock(Program* program) {
        if (!program || !program->getMemory()) return Address();
        for (MemoryBlock* block : program->getMemory()->getBlocks()) {
            Address start = block->getStart();
            if (!start.isValid()) continue;
            uint8_t buf[4] = {0};
            if (program->getMemory()->getBytes(start, buf, 4) != 4) continue;
            if (buf[0] == 'a' && buf[1] == 'r' && buf[2] == 't' && buf[3] == '\n') return start;
        }
        return Address();
    }
}

ArtAnalyzer::ArtAnalyzer()
    : AbstractAnalyzer("Android Runtime (ART) Annotation",
                       "Annotates Android Runtime (ART) header components.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool ArtAnalyzer::canAnalyze(Program* program) const {
    return findArtBlock(program).isValid();
}

bool ArtAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool ArtAnalyzer::added(Program* program, const AddressSetView& set,
                        TaskMonitor* monitor, MessageLog& log) {
    Address artAddress = findArtBlock(program);
    if (!artAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), artAddress, program);
    BinaryReader reader(std::move(provider), !program->getLanguage()->isBigEndian());

    // Validate magic
    std::string magic = reader.readAsciiString(0, 4);
    if (magic != "art\n") {
        log.append("Invalid ART file: bad magic");
        return false;
    }

    // Read version
    std::string version = reader.readAsciiString(4, 4);

    // Create basic header struct (magic + version)
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("ArtHeader_" + version, 0, dtm);
    headerType->add(&ByteDataType::dataType(), 4, "magic", nullptr);
    headerType->add(&ByteDataType::dataType(), 4, "version", nullptr);

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve ART header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(artAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create ART header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated ART image at " + artAddress.toString());
    }

    return true;
}

} // namespace ghidra
