#include <ghidra/RustDemanglerAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <string>
#include <vector>
#include <sstream>

namespace ghidra {

RustDemanglerAnalyzer::RustDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Rust Demangler", "Demangles Rust symbols.") {
}

bool RustDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

static std::string demangleRust(const std::string& mangled) {
    if (mangled.size() < 4) return "";

    std::string ident;
    size_t start = 0;

    if (mangled.compare(0, 4, "_RNC") == 0 || mangled.compare(0, 4, "_RNv") == 0 ||
        mangled.compare(0, 4, "_RNc") == 0 || mangled.compare(0, 4, "_RNs") == 0 ||
        mangled.compare(0, 4, "_RNm") == 0 || mangled.compare(0, 4, "_RNb") == 0 ||
        mangled.compare(0, 4, "_RNF") == 0 || mangled.compare(0, 4, "_RNt") == 0) {
        start = 4;
    } else if (mangled.compare(0, 2, "_R") == 0) {
        start = 2;
    } else {
        return "";
    }

    std::stringstream ss;
    size_t i = start;
    while (i < mangled.size()) {
        if (mangled[i] >= '0' && mangled[i] <= '9') {
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (!ss.str().empty()) ss << "::";
            ss << mangled.substr(i, len);
            i += len;
        } else if (mangled[i] == 'E') {
            break;
        } else if (mangled[i] == 'h') {
            ss << "::";
            ++i;
        } else if (mangled[i] == 's') {
            if (!ss.str().empty()) ss << "::";
            ss << "str";
            ++i;
        } else if (mangled[i] == 'u') {
            if (!ss.str().empty()) ss << "::";
            ss << "()";
            ++i;
        } else {
            ++i;
        }
    }

    return ss.str().empty() ? "" : ss.str();
}

bool RustDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling Rust symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 2 && name[0] == '_' && name[1] == 'R') {
            std::string demangled = demangleRust(name);
            if (!demangled.empty()) {
                symTable->createLabel(sym->getAddress(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    if (monitor) monitor->setMessage("Demangled " + std::to_string(count) + " Rust symbols.");
    return true;
}

} // namespace ghidra
