#include <ghidra/MicrosoftDemanglerAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <string>
#include <vector>
#include <windows.h>
#include <dbghelp.h>

namespace ghidra {

MicrosoftDemanglerAnalyzer::MicrosoftDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Microsoft Demangler", "Demangles MSVC C++ symbols using UnDecorateSymbolName.") {
}

bool MicrosoftDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

static std::string demangleMicrosoft(const std::string& mangled) {
    if (mangled.empty() || mangled[0] != '?') return "";

    char buffer[4096];
    DWORD result = UnDecorateSymbolName(
        mangled.c_str(),
        buffer,
        sizeof(buffer),
        UNDNAME_NO_ACCESS_SPECIFIERS |
        UNDNAME_NO_MEMBER_TYPE |
        UNDNAME_NO_THROW_SIGNATURES);

    if (result > 0) {
        return std::string(buffer, result);
    }
    return "";
}

bool MicrosoftDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling MSVC C++ symbols using UnDecorateSymbolName...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (!name.empty() && name[0] == '?') {
            std::string demangled = demangleMicrosoft(name);
            if (!demangled.empty()) {
                symTable->createLabel(sym->getAddress(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    Msg::info(getName(), "Demangled " + std::to_string(count) + " MSVC symbols using UnDecorateSymbolName.");
    return true;
}

} // namespace ghidra