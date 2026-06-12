#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

namespace {

bool isGoodFunctionStart(const Program* program, const Address& addr) {
    auto* listing = program->getListing();
    if (!listing) return false;

    if (!listing->getInstructionAt(addr)) return false;

    Address addrBefore = addr.previous();
    if (!addrBefore.isValid()) return true;

    Instruction* prevInstr = listing->getInstructionContaining(addrBefore);
    if (prevInstr && prevInstr->getFallThrough().isValid() &&
        prevInstr->getFallThrough() == addr) {
        return false;
    }

    return true;
}

} // anonymous namespace

ExternalEntryFunctionAnalyzer::ExternalEntryFunctionAnalyzer()
    : AbstractAnalyzer("External Entry References",
                       "Creates function definitions for external entry points where instructions already exist.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before().before());
    setDefaultEnablement(true);
}

bool ExternalEntryFunctionAnalyzer::added(Program* program, const AddressSetView& set,
                                           TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* symTable = program->getSymbolTable();
    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    if (!symTable || !listing || !funcMgr) return false;

    if (monitor) {
        monitor->setMessage("Finding External Entry Functions");
    }

    AddressSet funcStarts;

    auto entryPoints = symTable->getExternalEntryPoints();
    for (const Address& entry : entryPoints) {
        if (monitor && monitor->isCancelled()) return false;

        if (!set.contains(entry)) continue;

        if (!isGoodFunctionStart(program, entry)) continue;

        funcStarts.add(entry);
    }

    // Remove addresses that are already functions
    AddressSet alreadyFuncSet;
    for (const Address& entry : entryPoints) {
        if (funcStarts.contains(entry) && funcMgr->getFunctionAt(entry)) {
            alreadyFuncSet.add(entry);
        }
    }
    funcStarts.remove(alreadyFuncSet);

    if (monitor && monitor->isCancelled()) return false;

    // Create functions at the remaining entry points
    if (!funcStarts.isEmpty()) {
        auto* rangeIter = funcStarts.getAddressRanges(true);
        while (rangeIter->hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            const AddressRange& range = rangeIter->next();
            Address addr = range.getMinAddress();
            while (addr <= range.getMaxAddress()) {
                funcMgr->createFunction("", addr, AddressSet(addr, addr),
                                        SourceType::ANALYSIS);
                if (addr == range.getMaxAddress()) break;
                addr = addr.next();
            }
        }
    }

    return true;
}

} // namespace ghidra
