#include <ghidra/SwiftDemanglerAnalyzer.h>
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

namespace ghidra {

SwiftDemanglerAnalyzer::SwiftDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Swift Demangler", "Demangles Swift symbols.") {
}

bool SwiftDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

static std::string demangleSwift(const std::string& mangled) {
    if (mangled.empty()) return "";

    size_t start = 0;
    if (mangled.compare(0, 3, "_$s") == 0) {
        start = 3;
    } else if (mangled.compare(0, 2, "_T") == 0) {
        start = 2;
    } else if (mangled.compare(0, 4, "$S") == 0) {
        start = 2;
    } else if (mangled.compare(0, 4, "_$S") == 0) {
        start = 3;
    } else {
        return "";
    }

    std::string result;
    size_t i = start;
    while (i < mangled.size()) {
        if (mangled[i] == 's') {
            result += "Swift.";
            ++i;
        } else if (mangled[i] == 'S') {
            result += "Swift.";
            ++i;
        } else if (mangled[i] >= '0' && mangled[i] <= '9') {
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (!result.empty() && result.back() != '.') result += ".";
            result += mangled.substr(i, len);
            i += len;
        } else if (mangled[i] == 'y') {
            result += "->";
            ++i;
        } else if (mangled[i] == 'F') {
            result += "()";
            ++i;
        } else if (mangled[i] == 'o') {
            result += "->";
            ++i;
        } else if (mangled[i] == 'x') {
            ++i;
        } else if (mangled[i] == 'X') {
            ++i;
        } else if (mangled[i] == 'f') {
            result += "->";
            ++i;
        } else if (mangled[i] == 'z') {
            result += "(";
            ++i;
            while (i < mangled.size() && mangled[i] != 'z') {
                result += mangled[i];
                ++i;
            }
            if (i < mangled.size() && mangled[i] == 'z') {
                result += ")";
                ++i;
            }
        } else {
            ++i;
        }
    }

    return result.empty() ? "" : result;
}

bool SwiftDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling Swift symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 2 &&
            ((name[0] == '_' && (name.compare(0, 3, "_$s") == 0 || name.compare(0, 2, "_T") == 0)) ||
             (name[0] == '$'))) {
            std::string demangled = demangleSwift(name);
            if (!demangled.empty()) {
                symTable->createLabel(sym->getAddress(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    if (monitor) monitor->setMessage("Demangled " + std::to_string(count) + " Swift symbols.");
    return true;
}

} // namespace ghidra
