#include <ghidra/GnuDemanglerAnalyzer.h>
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
#include <vector>
#include <cxxabi.h>
#include <cstdlib>

namespace ghidra {

GnuDemanglerAnalyzer::GnuDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("GNU C++ Demangler", "Demangles Itanium/GNU C++ symbols using __cxa_demangle.") {
}

bool GnuDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

static std::string demangleGnu(const std::string& mangled) {
    if (mangled.size() < 3 || mangled[0] != '_' || mangled[1] != 'Z') {
        return "";
    }

    int status = -1;
    char* result = abi::__cxa_demangle(mangled.c_str(), nullptr, nullptr, &status);
    if (status == 0 && result) {
        std::string demangled(result);
        std::free(result);
        return demangled;
    }

    return "";
}

bool GnuDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling GNU C++ symbols using __cxa_demangle...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    NamingService naming(program);
    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 3 && name[0] == '_' && name[1] == 'Z') {
            std::string demangled = demangleGnu(name);
            if (!demangled.empty()) {
                naming.assignAlias(sym->getAddress().getOffset(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    Msg::info(getName(), "Demangled " + std::to_string(count) + " GNU C++ symbols using __cxa_demangle.");
    return true;
}

} // namespace ghidra