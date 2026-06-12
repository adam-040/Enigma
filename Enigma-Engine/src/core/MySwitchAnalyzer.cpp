#include <ghidra/MySwitchAnalyzer.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Msg.h>

namespace ghidra {

MySwitchAnalyzer::MySwitchAnalyzer(Program* program)
    : program_(program) {
}

bool MySwitchAnalyzer::analyze(Program* program, const Address& functionEntry,
                                TaskMonitor* monitor) {
    if (!program || !program->getMemory()) return false;
    return true;
}

bool MySwitchAnalyzer::resolvedFlow(const Address& flowFrom, const Address& destAddr,
                                     TaskMonitor* monitor) {
    addReference(flowFrom, destAddr);
    return true;
}

std::vector<Address> MySwitchAnalyzer::unresolvedIndirectFlow(const Address& instrAddr,
                                                                uint64_t destination,
                                                                int entrySize,
                                                                TaskMonitor* monitor) {
    return handleOffsetSwitch(instrAddr, destination, entrySize, monitor);
}

std::vector<Address> MySwitchAnalyzer::handleOffsetSwitch(const Address& instrAddr,
                                                            uint64_t destValue,
                                                            int entrySize,
                                                            TaskMonitor* monitor) {
    std::vector<Address> resolved;

    if (!program_) return resolved;

    Memory* memory = program_->getMemory();
    if (!memory) return resolved;

    const AddressSpace* defaultSpace = program_->getAddressFactory()->getDefaultAddressSpace();
    AddressSpace* space = const_cast<AddressSpace*>(defaultSpace);

    Address tableAddr(space, static_cast<int64_t>(destValue));
    MemoryBlock* block = memory->getBlock(tableAddr);
    if (!block) return resolved;

    int maxEntries = 256 / entrySize;
    if (maxEntries > 64) maxEntries = 64;

    uint8_t buf[256];
    int read = block->getBytes(tableAddr, buf, maxEntries * entrySize);
    if (read <= 0) return resolved;

    int entryCount = read / entrySize;

    for (int i = 0; i < entryCount; ++i) {
        uint64_t entryVal = 0;
        int byteOff = i * entrySize;
        for (int j = 0; j < entrySize; ++j) {
            entryVal |= static_cast<uint64_t>(buf[byteOff + j]) << (j * 8);
        }

        Address targetAddr(space, static_cast<int64_t>(entryVal));
        if (!memory->getBlock(targetAddr)) continue;
        if (program_->getListing()->isUndefined(targetAddr)) continue;

        resolved.push_back(targetAddr);
        addReference(instrAddr, targetAddr);
    }

    return resolved;
}

void MySwitchAnalyzer::addReference(const Address& flowFrom, const Address& toAddr) {
    if (!program_) return;

    auto* refMgr = program_->getReferenceManager();
    if (!refMgr) return;

    Instruction* fromInstr = program_->getListing()->getInstructionAt(flowFrom);
    if (!fromInstr) return;

    bool exists = false;
    for (auto* ref : fromInstr->getReferencesFrom()) {
        if (ref && ref->getToAddress() == toAddr) {
            exists = true;
            break;
        }
    }

    if (!exists) {
        refMgr->addMemoryReference(flowFrom, toAddr, &RefTypes::COMPUTED_CALL,
                                    SourceType::ANALYSIS, -1);
    }
}

} // namespace ghidra
