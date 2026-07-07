#include <ghidra/ArmSymbolAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Register.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/SourceType.h>
#include <ghidra/AutoNaming.h>

namespace ghidra {

ArmSymbolAnalyzer::ArmSymbolAnalyzer()
    : AbstractAnalyzer("ARM Symbol",
                       "Analyze bytes for Thumb symbols and shift -1 as necessary.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before().before());
    setDefaultEnablement(true);
}

bool ArmSymbolAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    if (program->getLanguage()->getProcessor().getName() != "ARM") return false;
    return program->getRegister("TMode") != nullptr;
}

bool ArmSymbolAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool ArmSymbolAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    monitor->setMessage("ARM/Thumb symbol analyzer");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    SymbolTable* symbolTable = program->getSymbolTable();
    if (!symbolTable) return false;

    SymbolIterator it = symbolTable->getAllProgramSymbols(true);
    while (it.hasNext() && !monitor->isCancelled()) {
        Symbol* primarySymbol = it.next();
        Address address = primarySymbol->getAddress();

        if (!address.isMemoryAddress()) continue;
        if (!set.contains(address)) continue;

        MemoryBlock* block = memory->getBlock(address);
        if (block == nullptr || !block->isExecute()) continue;

        if ((address.getOffset() & 0x01) != 0x01) continue;

        Address newAddress = address.subtract(1L);

        moveFunction(program, address, newAddress);
        moveSymbols(program, address, newAddress);
        updateEntryPoint(program, address, newAddress);
        setTModeRegister(program, newAddress);
    }

    return true;
}

void ArmSymbolAnalyzer::setTModeRegister(Program* program, const Address& newAddress) {
    Listing* listing = program->getListing();
    if (!listing) return;

    Register* tModeRegister = program->getRegister("TMode");
    if (!tModeRegister) return;

    if (listing->getDataAt(newAddress) == nullptr) {
        ProgramContext* context = program->getProgramContext();
        if (context) {
            context->setValue(tModeRegister, 1, newAddress, newAddress);
        }
    }
}

void ArmSymbolAnalyzer::updateEntryPoint(Program* program, const Address& address,
                                          const Address& newAddress) {
    SymbolTable* symbolTable = program->getSymbolTable();
    if (!symbolTable) return;

    if (symbolTable->isExternalEntryPoint(address)) {
        symbolTable->removeExternalEntryPoint(address);
        symbolTable->addExternalEntryPoint(newAddress);
    }
}

void ArmSymbolAnalyzer::moveSymbols(Program* program, const Address& address,
                                     const Address& newAddress) {
    SymbolTable* symbolTable = program->getSymbolTable();
    if (!symbolTable) return;

    Symbol* primary = symbolTable->getPrimarySymbol(address);
    if (primary == nullptr || primary->getSource() == SourceType::DEFAULT) {
        return;
    }

    createLabel(symbolTable, newAddress, primary->getName(), primary->getSource());

    std::vector<Symbol*> symbols = symbolTable->getSymbols(address);
    for (Symbol* s : symbols) {
        if (s != primary) {
            createLabel(symbolTable, newAddress, s->getName(), s->getSource());
            symbolTable->removeSymbolSpecial(s);
        }
    }
    symbolTable->removeSymbolSpecial(primary);
}

void ArmSymbolAnalyzer::moveFunction(Program* program, const Address& address,
                                      const Address& newAddress) {
    FunctionManager* functionManager = program->getFunctionManager();
    if (!functionManager) return;

    Function* func = functionManager->getFunctionAt(address);
    if (func != nullptr) {
        functionManager->removeFunction(address);
        functionManager->removeFunction(newAddress);

        try {
            AddressSet body(newAddress);
            functionManager->createFunction(AutoNaming::name("func", newAddress), newAddress, body, SourceType::DEFAULT);
        } catch (const std::exception&) {
            // Ignore errors creating the function at the corrected address
        }
    }
}

void ArmSymbolAnalyzer::createLabel(SymbolTable* symbolTable, const Address& address,
                                     const std::string& name, SourceType sourceType) {
    symbolTable->createLabel(address, name, sourceType);
}

void ArmSymbolAnalyzer::analysisEnded(Program* program) {
}

} // namespace ghidra
