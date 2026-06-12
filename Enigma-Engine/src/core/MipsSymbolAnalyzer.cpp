#include <ghidra/MipsSymbolAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Register.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/ContextChangeException.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>

namespace ghidra {

MipsSymbolAnalyzer::MipsSymbolAnalyzer()
    : AbstractAnalyzer("MIPS Symbol",
                       "Analyze bytes for Mips16 symbols and shift -1 as necessary.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before().before());
    setDefaultEnablement(true);
}

bool MipsSymbolAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    auto* lang = program->getLanguage();
    if (!lang) return false;
    Processor proc = lang->getProcessor();
    return (proc == Processor("MIPS") || proc == Processor("mips")) &&
           program->getRegister("ISA_MODE") != nullptr;
}

bool MipsSymbolAnalyzer::getDefaultEnablement(Program* program) const {
    return true;
}

void MipsSymbolAnalyzer::analysisEnded(Program* program) {
}

bool MipsSymbolAnalyzer::added(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    if (monitor) {
        monitor->setMessage("Mips16 symbol analyzer");
    }

    Register* IsaModeRegister = program->getRegister("ISA_MODE");
    if (!IsaModeRegister) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* functionManager = program->getFunctionManager();
    SymbolTable* symbolTable = program->getSymbolTable();
    ProgramContext* context = program->getProgramContext();

    if (!memory || !listing || !functionManager || !symbolTable || !context) {
        return false;
    }

    AddressSet redo;

    SymbolIterator allSymbolsIter = symbolTable->getAllProgramSymbols(true);
    while (allSymbolsIter.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        Symbol* symbol = allSymbolsIter.next();
        if (!symbol) continue;

        Address memAddr = symbol->getAddress();

        SourceType source = symbol->getSource();
        if (source != SourceType::IMPORTED) {
            continue;
        }

        if (!memAddr.isMemoryAddress()) {
            continue;
        }

        MemoryBlock* block = memory->getBlock(memAddr);
        if (!block || !block->isExecute()) {
            continue;
        }

        if ((memAddr.getOffset() & 0x01) == 0x01) {
            Address newAddr = memAddr.subtract(1);

            std::string name = symbol->getName();

            symbolTable->removeSymbolSpecial(symbol);

            Function* func = functionManager->getFunctionAt(memAddr);
            bool isFunc = (func != nullptr);
            if (isFunc) {
                functionManager->removeFunction(memAddr);
                functionManager->removeFunction(newAddr);
            }

            try {
                Symbol* newSymbol = symbolTable->createLabel(newAddr, name, SourceType::IMPORTED);
                if (newSymbol && isFunc) {
                    newSymbol->setPrimary(true);
                    AddressSet body(newAddr, newAddr);
                    try {
                        functionManager->createFunction(name, newAddr, body, SourceType::IMPORTED);
                    } catch (const std::runtime_error&) {
                    }
                }
            } catch (const std::exception&) {
            }

            if (symbolTable->isExternalEntryPoint(memAddr)) {
                symbolTable->removeExternalEntryPoint(memAddr);
                symbolTable->addExternalEntryPoint(newAddr);
            }

            if (listing->isUndefined(newAddr)) {
                try {
                    context->setValue(IsaModeRegister, 1, newAddr, newAddr);
                    redo.add(newAddr);
                } catch (const ContextChangeException&) {
                }
            }
        }
    }

    if (!redo.isEmpty()) {
        AutoAnalysisManager* mgr = AutoAnalysisManager::getAnalysisManager(program);
        if (mgr) {
            mgr->reAnalyzeAll(redo);
        }
    }

    return true;
}

} // namespace ghidra
