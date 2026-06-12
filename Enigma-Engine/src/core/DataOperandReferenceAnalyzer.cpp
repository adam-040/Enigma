#include <ghidra/DataOperandReferenceAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

DataOperandReferenceAnalyzer::DataOperandReferenceAnalyzer()
    : AbstractAnalyzer("Data Reference",
                       "Analyzes data referenced by data.",
                       AnalyzerType::DATA_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.after().after());
}

bool DataOperandReferenceAnalyzer::added(Program* program, const AddressSetView& set,
                                          TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* memory = program->getMemory();
    if (!listing || !refMgr || !memory) return false;

    auto dataItems = listing->getData(set);
    if (monitor) {
        monitor->initialize(static_cast<int4>(dataItems.size()));
    }

    int ptrSize = program->getDefaultPointerSize();

    for (size_t i = 0; i < dataItems.size(); ++i) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) {
            monitor->setProgress(static_cast<int4>(i + 1));
        }

        Data* data = dataItems[i];
        if (!data || !data->isDefined()) continue;

        if (!data->isPointer()) continue;

        // Read pointer value from memory
        uint8_t buf[8] = {};
        int bytesRead = memory->getBytes(data->getAddress(), buf, ptrSize);
        if (bytesRead < ptrSize) continue;

        // Convert raw bytes to address
        uint64_t val = 0;
        if (memory->isBigEndian()) {
            for (int j = 0; j < ptrSize; ++j) {
                val = (val << 8) | buf[j];
            }
        } else {
            for (int j = ptrSize - 1; j >= 0; --j) {
                val = (val << 8) | buf[j];
            }
        }

        if (val == 0) continue;

        AddressSpace* defaultSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());
    if (!defaultSpace) continue;

    Address value(defaultSpace, static_cast<int64_t>(val));

    // Check if target address is in valid memory
    MemoryBlock* block = memory->getBlock(value);
    if (!block) continue;

    // Create a memory reference from the data location to the target
    const RefType* refType = RefTypeFactory::getDefaultMemoryRefType(
        data, 0, value, false);
    if (refType) {
        refMgr->addMemoryReference(data->getAddress(), value,
                                   refType,
                                   SourceType::ANALYSIS, 0);
    }
    }

    return true;
}

} // namespace ghidra
