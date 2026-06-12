#include <ghidra/Pic24DInitAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/MemoryBufferImpl.h>
#include <ghidra/GhidraDataConverter.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <ghidra/SourceType.h>

namespace ghidra {

Pic24DInitAnalyzer::Pic24DInitAnalyzer()
    : AbstractAnalyzer("DInit Analyzer",
                       "Processes .dinit Data Initialization Section",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::BLOCK_ANALYSIS.before());
}

bool Pic24DInitAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;

    std::string procName = program->getLanguage()->getProcessor().getName();
    bool isSupported = (procName == "PIC-24" ||
                        procName.find("dsPIC3") == 0);
    if (!isSupported) return false;

    return program->getMemory()->getBlock(".dinit") != nullptr;
}

bool Pic24DInitAnalyzer::added(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Listing* listing = program->getListing();
    ReferenceManager* refMgr = program->getReferenceManager();
    Memory* memory = program->getMemory();
    DataTypeManager* dtm = program->getDataTypeManager();

    MemoryBlock* dinitBlock = memory->getBlock(".dinit");
    if (!dinitBlock) return true;

    if (listing->getDefinedDataContaining(dinitBlock->getStart()) != nullptr) {
        Msg::info(getName(), "Skipping .dinit processing due to existing data at " +
                        dinitBlock->getStart().toString());
        return true;
    }

    MemoryBufferImpl memBuffer(memory, dinitBlock->getStart());
    const GhidraDataConverter* converter =
        GhidraDataConverter::getConverter(program->getLanguage()->isBigEndian());

    StructureDataType* dataRecordType = new StructureDataType("data_record", 0, dtm);
    dataRecordType->setPackingEnabled(true);
    dataRecordType->add(&PointerDataType::dataType(), "dst", "");
    dataRecordType->add(&LongDataType::dataType(), "len", "");
    dataRecordType->addBitField(&LongDataType::dataType(), 7, "format", "");
    dataRecordType->addBitField(&LongDataType::dataType(), 9, "page", "");
    dataRecordType->add(new ArrayDataType(&ByteDataType::dataType(), 0, -1), "data", "");

    DataType* resolvedType = dtm->resolve(dataRecordType, nullptr);
    if (!resolvedType) {
        log.append("Failed to resolve data_record type");
        return false;
    }
    int recordLength = resolvedType->getLength();
    if (recordLength <= 0) {
        log.append("Invalid data_record length");
        return false;
    }

    AddressSpace* dataSpace = program->getLanguage()->getDefaultDataSpace();
    if (!dataSpace) {
        log.append("No default data space");
        return false;
    }

    Address addr = dinitBlock->getStart();
    int64_t available = dinitBlock->getSize();
    int offset = 0;

    while (offset < available) {
        if (monitor && monitor->isCancelled()) return false;

        int16_t dst = converter->getShort(&memBuffer, offset);
        if (dst == 0) break;

        Data* dataRecord = listing->createData(addr, resolvedType, recordLength);
        if (!dataRecord) {
            log.append("Failed to create data record at " + addr.toString());
            break;
        }

        Reference* oldRef = refMgr->getPrimaryReferenceFrom(addr, 0);
        if (oldRef) {
            refMgr->deleteReference(oldRef);
        }

        Address dstAddr(dataSpace, static_cast<int64_t>(dst & 0x0ffff));
        refMgr->addMemoryReference(addr, dstAddr, &RefTypes::DATA, SourceType::ANALYSIS, 0);

        offset += recordLength;
        addr = addr.add(recordLength);
    }

    return true;
}

} // namespace ghidra
