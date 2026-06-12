#include <ghidra/FunctionStartPreFuncAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

namespace ghidra {

FunctionStartPreFuncAnalyzer::FunctionStartPreFuncAnalyzer()
    : AbstractAnalyzer("Function Start Search Pre-Function",
                       "Pre-function discovery variant of function start search.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS.before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FunctionStartPreFuncAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FunctionStartPreFuncAnalyzer::added(Program* program, const AddressSetView& set,
                                          TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Finding function starts from symbols...");

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !symTable || !funcMgr) return true;

    int found = 0;
    SymbolIterator symIter = symTable->getAllProgramSymbols(true);
    while (symIter.hasNext() && !monitor->isCancelled()) {
        Symbol* sym = symIter.next();
        Address symAddr = sym->getAddress();
        if (!symAddr.isValid()) continue;
        if (!memory->getBlock(symAddr)) continue;
        if (funcMgr->getFunctionAt(symAddr) || funcMgr->getFunctionContaining(symAddr)) continue;

        MemoryBlock* block = memory->getBlock(symAddr);
        if (!block || !block->isExecute()) continue;

        // Check if the symbol looks like a function entry (not a data label)
        if (sym->getSource() != SourceType::DEFAULT && sym->getSource() != SourceType::IMPORTED) {
            AddressSet body(symAddr, symAddr);
            funcMgr->createFunction("sym_" + sym->getName(), symAddr, body, SourceType::ANALYSIS);
            ++found;
        }
    }

    if (found > 0) {
        Msg::info(getName(), "Found " + std::to_string(found) + " function starts from symbols.");
    }
    return true;
}

} // namespace ghidra
