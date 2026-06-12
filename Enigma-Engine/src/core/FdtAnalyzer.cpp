#include <ghidra/FdtAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/Language.h>
#include <ghidra/MemoryByteProvider.h>
#include <ghidra/BinaryReader.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <memory>

namespace ghidra {

FdtAnalyzer::FdtAnalyzer()
    : AbstractAnalyzer("Flattened Device Tree (FDT/DTB/DTBO) Analyzer",
                       "Analyzes Flattened Device Tree (FDT) files.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool FdtAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getMemory()) return false;
    Address minAddr = program->getMinAddress();
    if (!minAddr.isValid()) return false;
    MemoryBlock* block = program->getMemory()->getBlock(minAddr);
    if (!block || !block->isInitialized()) return false;
    uint8_t buf[4] = {0};
    if (program->getMemory()->getBytes(minAddr, buf, 4) != 4) return false;
    return buf[0] == 0xD0 && buf[1] == 0x0D && buf[2] == 0xFE && buf[3] == 0xED;
}

bool FdtAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool FdtAnalyzer::added(Program* program, const AddressSetView& set,
                        TaskMonitor* monitor, MessageLog& log) {
    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    auto provider = std::make_unique<MemoryByteProvider>(program->getMemory(), minAddress, program);
    BinaryReader reader(std::move(provider), true); // FDT is always big-endian

    // Validate magic
    uint32_t magic = reader.readUnsignedInt(0);
    if (magic != 0xD00DFEED) {
        log.append("Invalid FDT file: bad magic");
        return false;
    }

    // Read version to determine header size
    int version = reader.readInt(24); // version is at offset 24
    int lastCompVersion = reader.readInt(28);

    // Create header struct (version-dependent fields)
    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* headerType = new StructureDataType("fdt_header", 0, dtm);

    headerType->add(&DWordDataType::dataType(), 4, "magic", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "totalsize", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "off_dt_struct", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "off_dt_strings", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "off_mem_rsvmap", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "version", nullptr);
    headerType->add(&DWordDataType::dataType(), 4, "last_comp_version", nullptr);

    if (version >= 2) {
        headerType->add(&DWordDataType::dataType(), 4, "boot_cpuid_phys", nullptr);
    }
    if (version >= 3) {
        headerType->add(&DWordDataType::dataType(), 4, "size_dt_strings", nullptr);
    }
    if (version >= 17) {
        headerType->add(&DWordDataType::dataType(), 4, "size_dt_struct", nullptr);
    }

    DataType* resolvedType = dtm->resolve(headerType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve FDT header type");
        return false;
    }

    Data* headerData = program->getListing()->createData(minAddress, resolvedType);
    if (!headerData) {
        log.append("Failed to create FDT header data");
        return false;
    }

    if (monitor) {
        monitor->setMessage("Annotated flattened device tree at " + minAddress.toString());
    }

    return true;
}

} // namespace ghidra
