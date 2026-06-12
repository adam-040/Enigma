#include <ghidra/AddressTableAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Data.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressRange.h>
#include <ghidra/AddressRangeIterator.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

AddressTableAnalyzer::AddressTableAnalyzer()
    : AbstractAnalyzer("Create Address Tables",
                       "Analyzes undefined data for address tables.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.before());
    setSupportsOneTimeAnalysis();
    setDefaultEnablement(false);
}

bool AddressTableAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    AddressFactory* af = program->getAddressFactory();
    if (!af) return false;
    AddressSpace* defaultSpace = const_cast<AddressSpace*>(af->getDefaultAddressSpace());
    if (!defaultSpace) return false;
    int addrSize = defaultSpace->getSize();
    return (addrSize == 32 || addrSize == 64);
}

bool AddressTableAnalyzer::added(Program* program, const AddressSetView& addrSet,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* memory = program->getMemory();
    auto* refMgr = program->getReferenceManager();
    if (!listing || !memory || !refMgr) return false;

    long addrCount = memory->getSize();
    if (monitor) {
        monitor->initialize(addrCount);
        monitor->setMessage("Analyze Address Tables");
    }

    uint8_t ptrSize = static_cast<uint8_t>(program->getDefaultPointerSize());
    long progress = 0;

    auto* rangeIter = addrSet.getAddressRanges(true);
    while (rangeIter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        const AddressRange& range = rangeIter->next();
        Address start = range.getMinAddress();

        while (start <= range.getMaxAddress()) {
            if (monitor && monitor->isCancelled()) break;
            progress++;
            if (monitor && (progress % 2048) == 1) {
                monitor->setProgress(progress);
                monitor->setMessage("Analyze Tables " + start.toString());
            }

            if (start.getOffset() % tableAlignment_ != 0) {
                if (start == range.getMaxAddress()) break;
                start = start.next();
                continue;
            }

            if (listing->getDefinedDataContaining(start) || listing->getInstructionAt(start)) {
                if (start == range.getMaxAddress()) break;
                start = start.next();
                continue;
            }

            if (processAddressTable(program, start, monitor)) {
                int64_t skipBytes = static_cast<int64_t>(minimumTableSize_ * ptrSize);
                if (skipBytes > 0) {
                    if (start.getOffset() + skipBytes > range.getMaxAddress().getOffset()) break;
                    start = Address(start.getAddressSpace(),
                                     start.getOffset() + skipBytes);
                    continue;
                }
            }

            if (start == range.getMaxAddress()) break;
            start = start.next();
        }
    }

    return true;
}

bool AddressTableAnalyzer::processAddressTable(Program* program, const Address& start,
                                                TaskMonitor* monitor) {
    auto* memory = program->getMemory();
    auto* refMgr = program->getReferenceManager();
    if (!memory || !refMgr) return false;

    uint8_t ptrSize = static_cast<uint8_t>(program->getDefaultPointerSize());
    if (ptrSize < 1 || ptrSize > 8) return false;

    AddressSpace* defaultSpace = const_cast<AddressSpace*>(
        program->getAddressFactory()->getDefaultAddressSpace());
    if (!defaultSpace) return false;

    int consecutivePointers = 0;
    std::vector<Address> tableEntries;

    for (int i = 0; i < 256; ++i) {
        if (monitor && monitor->isCancelled()) break;

        Address current(start.getAddressSpace(),
                         start.getOffset() + i * ptrSize);

        if (current.getOffset() % ptrAlignment_ != 0) break;

        uint8_t buf[8] = {};
        int bytesRead = memory->getBytes(current, buf, ptrSize);
        if (bytesRead < ptrSize) break;

        uint64_t val = 0;
        if (memory->isBigEndian()) {
            for (int j = 0; j < ptrSize; ++j) val = (val << 8) | buf[j];
        } else {
            for (int j = ptrSize - 1; j >= 0; --j) val = (val << 8) | buf[j];
        }

        if (val < static_cast<uint64_t>(minPointerAddress_) || val == 0) {
            if (consecutivePointers >= minimumTableSize_) break;
            consecutivePointers = 0;
            tableEntries.clear();
            continue;
        }

        if (!tableEntries.empty()) {
            Address lastAddr = tableEntries.back();
            uint8_t lastBuf[8] = {};
            memory->getBytes(lastAddr, lastBuf, ptrSize);
            uint64_t lastVal = 0;
            if (memory->isBigEndian()) {
                for (int j = 0; j < ptrSize; ++j) lastVal = (lastVal << 8) | lastBuf[j];
            } else {
                for (int j = ptrSize - 1; j >= 0; --j) lastVal = (lastVal << 8) | lastBuf[j];
            }

            int64_t gap = static_cast<int64_t>(val - lastVal);
            if (gap < 0 || gap > maxPointerDistance_) break;
        }

        Address target(defaultSpace, static_cast<int64_t>(val));
        MemoryBlock* block = memory->getBlock(target);
        if (!block) {
            if (consecutivePointers >= minimumTableSize_) break;
            consecutivePointers = 0;
            tableEntries.clear();
            continue;
        }

        tableEntries.push_back(current);
        consecutivePointers++;
    }

    if (consecutivePointers >= minimumTableSize_ && !tableEntries.empty()) {
        for (const Address& entry : tableEntries) {
            uint8_t buf[8] = {};
            memory->getBytes(entry, buf, ptrSize);
            uint64_t val = 0;
            if (memory->isBigEndian()) {
                for (int j = 0; j < ptrSize; ++j) val = (val << 8) | buf[j];
            } else {
                for (int j = ptrSize - 1; j >= 0; --j) val = (val << 8) | buf[j];
            }

            Address target(defaultSpace, static_cast<int64_t>(val));
            const RefType* refType = RefTypeFactory::getDefaultMemoryRefType(
                nullptr, 0, target, false);
            refMgr->addMemoryReference(entry, target,
                                       refType,
                                       SourceType::ANALYSIS, 0);
        }

        if (autoLabelTable_ && !tableEntries.empty()) {
            program->getSymbolTable()->createLabel(
                tableEntries[0], "TABLE_" + start.toString(), SourceType::ANALYSIS);
        }

        if (createBookmarksEnabled_) {
            program->getBookmarkManager()->setBookmark(
                start, "Analysis", "Address Table Found");
        }

        return true;
    }

    return false;
}

void AddressTableAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerInt("Minimum Table Size", minimumTableSize_,
                        "Minimum number of consecutive addresses for a table.");
    options.registerInt("Table Alignment", tableAlignment_,
                        "Only check for tables aligned to this number of bytes.");
    options.registerInt("Pointer Alignment", ptrAlignment_,
                        "Check for ptr table entries aligned to this number of bytes.");
    options.registerBool("Auto Label Table", autoLabelTable_,
                         "Label the start of the table and each entry.");
    options.registerInt8("Minimum Pointer Address", minPointerAddress_,
                          "Minimum Address that any value is considered a pointer.");
    options.registerInt8("Maximum Pointer Distance", maxPointerDistance_,
                          "Maximum distance between pointers before table break.");
    options.registerBool("Create Analysis Bookmarks", createBookmarksEnabled_,
                         "Create bookmark at each address table location.");
}

void AddressTableAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Minimum Table Size"))
        minimumTableSize_ = options.getInt("Minimum Table Size");
    if (options.hasOption("Table Alignment"))
        tableAlignment_ = options.getInt("Table Alignment");
    if (options.hasOption("Pointer Alignment"))
        ptrAlignment_ = options.getInt("Pointer Alignment");
    if (options.hasOption("Auto Label Table"))
        autoLabelTable_ = options.getBool("Auto Label Table");
    if (options.hasOption("Minimum Pointer Address"))
        minPointerAddress_ = options.getInt8("Minimum Pointer Address");
    if (options.hasOption("Maximum Pointer Distance"))
        maxPointerDistance_ = options.getInt8("Maximum Pointer Distance");
    if (options.hasOption("Create Analysis Bookmarks"))
        createBookmarksEnabled_ = options.getBool("Create Analysis Bookmarks");
}

} // namespace ghidra
