#include <ghidra/iOS_FixupArmSymbolsAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/Memory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

iOS_FixupArmSymbolsAnalyzer::iOS_FixupArmSymbolsAnalyzer()
    : AbstractAnalyzer("Apple iOS ARM Symbol Fixup",
                       "Moves the pre-defined ARM symbols to image base of the iOS binary.",
                       AnalyzerType::BYTE_ANALYZER) {
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
}

bool iOS_FixupArmSymbolsAnalyzer::getDefaultEnablement(Program* program) const {
    return isBoot(program);
}

bool iOS_FixupArmSymbolsAnalyzer::canAnalyze(Program* program) const {
    return isBoot(program);
}

bool iOS_FixupArmSymbolsAnalyzer::isBoot(Program* program) const {
    if (!program || !program->getLanguage()) return false;

    if (program->getLanguage()->getProcessor().getName() != "ARM") return false;

    Address minAddress = program->getMinAddress();
    if (!minAddress.isValid()) return false;

    Address address = minAddress.add(0x200);
    if (!address.isValid()) return false;

    Memory* memory = program->getMemory();
    if (!memory) return false;

    uint8_t bytes[0x40] = {0};
    int nread = memory->getBytes(address, bytes, 0x40);
    if (nread != 0x40) return false;

    std::string s(reinterpret_cast<char*>(bytes), 0x40);
    s = s.substr(0, s.find('\0'));
    size_t pos = s.find("Apple");
    if (pos == std::string::npos) return false;

    if (s.find("SecureROM") == 0 || s.find("LLB") == 0 ||
        s.find("iBoot") == 0 || s.find("iBEC") == 0 || s.find("iBSS") == 0) {
        return true;
    }
    return false;
}

bool iOS_FixupArmSymbolsAnalyzer::added(Program* program, const AddressSetView& set,
                                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    SymbolTable* symbolTable = program->getSymbolTable();
    if (!symbolTable) return false;

    SymbolIterator symbolIterator = symbolTable->getAllProgramSymbols(true);
    while (symbolIterator.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        Symbol* symbol = symbolIterator.next();
        if (!symbol) continue;

        if (symbol->isPinned()) {
            symbol->setPinned(false);
        }
    }

    return true;
}

} // namespace ghidra
