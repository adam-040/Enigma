#include <ghidra/FunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

FunctionAnalyzer::FunctionAnalyzer()
    : AbstractAnalyzer("Subroutine References",
                       "Create Function definitions for code that is called.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS.before());
    setDefaultEnablement(true);
}

bool FunctionAnalyzer::isPlaceHolderFunctionThatShouldBeFixed(
    Program* program, Listing* listing, Function* func) const {
    if (!func) return false;
    if (func->getBody().getNumAddresses() > 1) return false;
    Instruction* instr = listing->getInstructionAt(func->getEntryPoint());
    if (!instr) return false;
    FlowType* ft = instr->getFlowType();
    if (instr->getLength() > 1 || (ft && !ft->isTerminal())) {
        return true;
    }
    return false;
}

bool FunctionAnalyzer::fallthroughCall(Program* program, Reference* ref) const {
    Address from = ref->getFromAddress();
    Instruction* instr = program->getListing()->getInstructionAt(from);
    if (!instr) return false;
    return instr->getFallThrough() == ref->getToAddress();
}

bool FunctionAnalyzer::isThunkFunction(Program* program, const Address& entry) const {
    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* funcMgr = program->getFunctionManager();
    if (!listing || !refMgr || !funcMgr) return false;

    Instruction* instr = listing->getInstructionAt(entry);
    if (!instr) return false;
    FlowType* ftype = instr->getFlowType();
    if (!ftype || !ftype->isJump()) return false;
    if (ftype->isCall()) return false;

    auto refs = refMgr->getFlowReferencesFrom(instr->getAddress());
    for (auto* ref : refs) {
        if (!ref) continue;
        const RefType* rtype = ref->getReferenceType();
        if (!rtype || !rtype->isJump()) continue;
        Address target = ref->getToAddress();
        if (target.isValid() && funcMgr->getFunctionAt(target)) {
            return true;
        }
    }
    return false;
}

bool FunctionAnalyzer::added(Program* program, const AddressSetView& set,
                             TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* refMgr = program->getReferenceManager();
    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    if (!refMgr || !listing || !funcMgr) return false;

    AddressSet funcStarts;

    int count = 0;
    int64_t initialCount = set.getNumAddresses();
    if (monitor) {
        monitor->initialize(initialCount);
    }
    AddressSet leftSet(set);

    auto iter = refMgr->getReferenceSourceIterator(set, true);
    while (iter && iter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;

        Address addr = iter->next();

        count++;
        if (count > NOTIFICATION_INTERVAL) {
            leftSet.deleteRange(leftSet.getMinAddress(), addr);
            if (monitor) {
                monitor->setProgress(initialCount - leftSet.getNumAddresses());
                monitor->setMessage(analysisMessage_ + addr.toString());
            }
            count = 0;
        }

        Instruction* instr = listing->getInstructionAt(addr);
        if (!instr) continue;
        FlowType* flowType = instr->getFlowType();
        if (!flowType || !flowType->isCall()) continue;

        auto refs = refMgr->getFlowReferencesFrom(addr);
        for (auto* ref : refs) {
            if (!ref) continue;
            const RefType* refType = ref->getReferenceType();
            if (!refType || !refType->isCall()) continue;

            Address entryAddr = ref->getToAddress();
            if (!entryAddr.isValid()) continue;

            if (fallthroughCall(program, ref)) continue;

            funcStarts.add(entryAddr);
        }
    }

    // Remove any addresses that are already functions (unless placeholder)
    AddressSet toRemove;
    AddressRangeIterator* rangeIter = funcStarts.getAddressRanges(true);
    while (rangeIter && rangeIter->hasNext()) {
        const AddressRange& range = rangeIter->next();
        Address addr = range.getMinAddress();
        Function* func = funcMgr->getFunctionAt(addr);
        if (!func) continue;
        if (isPlaceHolderFunctionThatShouldBeFixed(program, listing, func)) continue;
        toRemove.add(addr);
    }
    delete rangeIter;
    funcStarts.remove(toRemove);

    // If only creating thunks, filter to only thunk starts
    if (createOnlyThunks_ && !funcStarts.isEmpty()) {
        AddressSet thunkStarts;
        AddressRangeIterator* thunkRangeIter = funcStarts.getAddressRanges(true);
        while (thunkRangeIter && thunkRangeIter->hasNext()) {
            const AddressRange& range = thunkRangeIter->next();
            Address addr = range.getMinAddress();
            if (isThunkFunction(program, addr)) {
                thunkStarts.add(addr);
            }
        }
        delete thunkRangeIter;
        funcStarts = thunkStarts;
    }

    // Create functions
    if (!funcStarts.isEmpty()) {
        AddressRangeIterator* createIter = funcStarts.getAddressRanges(true);
        while (createIter && createIter->hasNext()) {
            const AddressRange& range = createIter->next();
            Address addr = range.getMinAddress();
            funcMgr->createFunction("", addr, AddressSet(addr, addr), SourceType::ANALYSIS);
        }
        delete createIter;
    }

    return true;
}

} // namespace ghidra
