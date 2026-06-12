#include <ghidra/CoffArchiveAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>

namespace ghidra {

CoffArchiveAnalyzer::CoffArchiveAnalyzer()
    : AbstractBinaryFormatAnalyzer("COFF Archive",
                                   "Analyzes COFF archive (.lib) files.") {
}

bool CoffArchiveAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "COFF Archive";
}

bool CoffArchiveAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing COFF archive...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[8] = {0};
    if (memory->getBytes(addr, magic, 8) != 8) return false;
    if (magic[0] != '!' || magic[1] != '<' || magic[2] != 'a' || magic[3] != 'r' ||
        magic[4] != 'c' || magic[5] != 'h' || magic[6] != '>' || magic[7] != '\n') return false;

    DataTypeManager* dtm = program->getDataTypeManager();
    StructureDataType* archiveHeader = new StructureDataType("COFF_Archive_Header", 0, dtm);
    archiveHeader->add(new ArrayDataType(&ByteDataType::dataType(), 8, 1, dtm), 8, "ar_name", "");

    DataType* resolvedType = dtm->resolve(archiveHeader, nullptr);
    if (!resolvedType) return false;

    Data* data = program->getListing()->createData(addr, resolvedType);
    if (data) data->setComment("COFF Archive Header");

    SymbolTable* symTable = program->getSymbolTable();
    symTable->createLabel(addr, "COFF_ARCHIVE_HEADER", SourceType::ANALYSIS);

    if (monitor) monitor->setMessage("COFF archive analysis complete.");
    return true;
}

} // namespace ghidra
