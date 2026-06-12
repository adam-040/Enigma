#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

EntryPointAnalyzer::EntryPointAnalyzer()
    : AbstractAnalyzer("Disassemble Entry Points",
                       "Disassembles entry points in newly added memory.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::BLOCK_ANALYSIS);
    setDefaultEnablement(true);
}

bool EntryPointAnalyzer::added(Program* program, const AddressSetView& addressSet,
                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    if (monitor) {
        monitor->initialize(addressSet.getNumAddresses());
    }

    std::vector<Address> doNowSet;
    std::vector<Address> dummySet;
    std::vector<Address> redoSet;

    findDummyFunctions(program, addressSet, dummySet, redoSet);
    doDisassembly(program, monitor, dummySet);
    addExternalEntryPoints(program, addressSet, doNowSet);
    addSymbolEntryPoints(program, addressSet, doNowSet);
    doDisassembly(program, monitor, doNowSet);

    if (!redoSet.empty()) {
        auto* funcMgr = program->getFunctionManager();
        auto* listing = program->getListing();
        for (const Address& entry : redoSet) {
            if (monitor && monitor->isCancelled()) break;
            Function* func = funcMgr->getFunctionAt(entry);
            if (!func) continue;
            if (!listing->getInstructionAt(entry)) continue;
            funcMgr->createFunction(func->getName(), entry,
                                     AddressSet(entry, entry),
                                     SourceType::ANALYSIS);
        }
    }

    return true;
}

void EntryPointAnalyzer::doDisassembly(Program* program, TaskMonitor* monitor,
                                        const std::vector<Address>& entries) {
    if (entries.empty() || !program) return;

    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    auto* symTable = program->getSymbolTable();
    if (!listing || !funcMgr || !symTable) return;

    for (const Address& entry : entries) {
        if (monitor && monitor->isCancelled()) return;
        if (!listing->isUndefined(entry)) continue;
        if (funcMgr->getFunctionAt(entry)) continue;
        funcMgr->createFunction("", entry, AddressSet(entry, entry), SourceType::ANALYSIS);
    }

    for (const Address& entry : entries) {
        if (monitor && monitor->isCancelled()) return;
        if (listing->getInstructionAt(entry) && !funcMgr->getFunctionAt(entry)) {
            if (symTable->isExternalEntryPoint(entry)) {
                funcMgr->createFunction("", entry, AddressSet(entry, entry),
                                        SourceType::ANALYSIS);
            }
        }
    }
}

void EntryPointAnalyzer::addExternalEntryPoints(Program* program, const AddressSetView& set,
                                                  std::vector<Address>& entries) {
    auto* symTable = program->getSymbolTable();
    if (!symTable) return;

    auto extPoints = symTable->getExternalEntryPoints();
    for (const Address& entry : extPoints) {
        if (set.contains(entry)) {
            Symbol* sym = symTable->getPrimarySymbol(entry);
            if (sym && sym->getSource() == SourceType::DEFAULT) {
                entries.push_back(entry);
            }
        }
    }
}

void EntryPointAnalyzer::addSymbolEntryPoints(Program* program, const AddressSetView& set,
                                                std::vector<Address>& entries) {
    auto* symTable = program->getSymbolTable();
    if (!symTable) return;

    SymbolIterator symIter = symTable->getAllProgramSymbols(true);
    while (symIter.hasNext()) {
        Symbol* sym = symIter.next();
        if (!sym) continue;
        Address addr = sym->getAddress();
        if (set.contains(addr)) {
            entries.push_back(addr);
        }
    }
}

void EntryPointAnalyzer::findDummyFunctions(Program* program, const AddressSetView& set,
                                              std::vector<Address>& dummySet,
                                              std::vector<Address>& redoSet) {
    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!funcMgr || !listing) return;

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    while (funcIter.hasNext()) {
        Function* func = funcIter.next();
        if (!func) continue;

        Address entry = func->getEntryPoint();
        const AddressSet& body = func->getBody();

        if (listing->getDefinedDataContaining(entry)) continue;

        if (body.getNumAddresses() == 1) {
            redoSet.push_back(entry);
        }

        if (!listing->getInstructionAt(entry)) {
            dummySet.push_back(entry);
        }
    }
}

void EntryPointAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Respect Execute Flag", respectExecuteFlags_,
                         "Respect Execute flag on memory blocks.");
}

void EntryPointAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Respect Execute Flag"))
        respectExecuteFlags_ = options.getBool("Respect Execute Flag");
}

} // namespace ghidra
