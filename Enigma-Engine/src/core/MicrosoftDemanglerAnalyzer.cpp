#include <ghidra/MicrosoftDemanglerAnalyzer.h>
#include <ghidra/MsvcDemangler.h>
#include <ghidra/Program.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/NamingService.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <string>

namespace ghidra {

MicrosoftDemanglerAnalyzer::MicrosoftDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Microsoft Demangler", "Demangles MSVC C++ symbols using pure C++ parser.") {
}

bool MicrosoftDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

bool MicrosoftDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling MSVC C++ symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    NamingService naming(program);
    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (MsvcDemangler::isMsvcMangled(name)) {
            std::string demangled = MsvcDemangler::demangle(name);
            if (!demangled.empty() && demangled != name) {
                naming.assignAlias(sym->getAddress().getOffset(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    Msg::info(getName(), "Demangled " + std::to_string(count) + " MSVC symbols using pure C++ parser.");
    return true;
}

} // namespace ghidra
