#include <ghidra/GnuDemanglerAnalyzer.h>
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

GnuDemanglerAnalyzer::GnuDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("GNU C++ Demangler", "Demangles Itanium/GNU C++ symbols.") {
}

bool GnuDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

static std::string demangleGnu(const std::string& mangled) {
    if (mangled.size() < 3 || mangled[0] != '_' || mangled[1] != 'Z') {
        return "";
    }
    std::string result = mangled.substr(2);
    std::string demangled;
    size_t i = 0;
    while (i < result.size()) {
        if (result[i] == 'v' && i == 0) {
            demangled += "void";
            ++i;
        } else if (result[i] == 'i' && i == 0) {
            demangled += "int";
            ++i;
        } else if (result[i] == 'c' && i == 0) {
            demangled += "char";
            ++i;
        } else if (result[i] == 'f' && i == 0) {
            demangled += "float";
            ++i;
        } else if (result[i] == 'd' && i == 0) {
            demangled += "double";
            ++i;
        } else if (result[i] == 'b' && i == 0) {
            demangled += "bool";
            ++i;
        } else if (result[i] == 'l' && i == 0) {
            demangled += "long";
            ++i;
        } else if (result[i] == 's' && i == 0) {
            demangled += "short";
            ++i;
        } else if (result[i] == 'm' && i == 0) {
            demangled += "unsigned __int128";
            ++i;
        } else if (result[i] == 'o' && i == 0) {
            demangled += "signed __int128";
            ++i;
        } else if (result[i] == 'w' && i == 0) {
            demangled += "wchar_t";
            ++i;
        } else if (result[i] == 'E') {
            demangled += " ...";
            ++i;
            break;
        } else if (result[i] == 'P') {
            demangled += "*";
            ++i;
        } else if (result[i] == 'R') {
            demangled += "&";
            ++i;
        } else if (result[i] == 'K') {
            demangled += " const";
            ++i;
        } else if (result[i] == 'N') {
            ++i;
            if (demangled.empty()) {
                while (i < result.size() && result[i] >= '0' && result[i] <= '9') {
                    i++;
                }
            }
        } else if (result[i] >= '1' && result[i] <= '9') {
            size_t len = 0;
            while (i < result.size() && result[i] >= '0' && result[i] <= '9') {
                len = len * 10 + (result[i] - '0');
                ++i;
            }
            if (!demangled.empty() && demangled.back() != ' ') demangled += "::";
            demangled += result.substr(i, len);
            i += len;
        } else {
            ++i;
        }
    }
    return demangled.empty() ? "" : demangled;
}

bool GnuDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling GNU C++ symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 3 && name[0] == '_' && name[1] == 'Z') {
            std::string demangled = demangleGnu(name);
            if (!demangled.empty()) {
                symTable->createLabel(sym->getAddress(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    if (monitor) monitor->setMessage("Demangled " + std::to_string(count) + " GNU C++ symbols.");
    return true;
}

} // namespace ghidra
