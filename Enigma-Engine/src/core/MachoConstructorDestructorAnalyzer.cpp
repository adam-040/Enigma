#include <ghidra/MachoConstructorDestructorAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

MachoConstructorDestructorAnalyzer::MachoConstructorDestructorAnalyzer()
    : AbstractAnalyzer("Mach-O Constructor/Destructor",
                       "Creates pointers to global constructors and destructors in a Mach-O file.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
}

bool MachoConstructorDestructorAnalyzer::canAnalyze(Program* program) const {
    return hasConstructorOrDestructorBlocks(program);
}

bool MachoConstructorDestructorAnalyzer::getDefaultEnablement(Program* program) const {
    return hasConstructorOrDestructorBlocks(program);
}

bool MachoConstructorDestructorAnalyzer::added(Program* program, const AddressSetView& set,
                                                TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    Listing* listing = program->getListing();
    if (!listing) return false;

    std::vector<MemoryBlock*> blocks = program->getMemory()->getBlocks();
    bool didWork = false;

    for (MemoryBlock* block : blocks) {
        if (!block) continue;
        const std::string& name = block->getName();
        if (name != "__constructor" && name != "__destructor") continue;

        Address currentAddr = block->getStart();
        const Address& endAddr = block->getEnd();

        while (!monitor->isCancelled()) {
            if (currentAddr > endAddr) break;

            Data* data = listing->createData(currentAddr, &PointerDataType::dataType());
            if (!data) break;

            currentAddr = currentAddr.add(data->getLength());
            didWork = true;
        }

        if (monitor->isCancelled()) return didWork;
    }

    return didWork;
}

bool MachoConstructorDestructorAnalyzer::hasConstructorOrDestructorBlocks(Program* program) const {
    if (!program || !program->getMemory()) return false;

    std::vector<MemoryBlock*> blocks = program->getMemory()->getBlocks();
    for (MemoryBlock* block : blocks) {
        if (!block) continue;
        const std::string& name = block->getName();
        if (name == "__constructor" || name == "__destructor") return true;
    }
    return false;
}

} // namespace ghidra
