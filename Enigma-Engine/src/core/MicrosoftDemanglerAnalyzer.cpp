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
#include <string>
#include <vector>

namespace ghidra {

MicrosoftDemanglerAnalyzer::MicrosoftDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Microsoft Demangler", "Demangles MSVC C++ symbols.") {
}

bool MicrosoftDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

static std::string demangleMicrosoft(const std::string& mangled) {
    if (mangled.empty() || mangled[0] != '?') return "";

    std::string result;
    size_t i = 1;

    if (i < mangled.size() && mangled[i] == '?') {
        result += "??";
        ++i;
    }

    while (i < mangled.size()) {
        if (mangled[i] == '@') {
            result += "::";
            ++i;
        } else if (mangled[i] == '$') {
            result += "$";
            ++i;
        } else if (mangled[i] == 'A') { ++i; }
        else if (mangled[i] == 'B' && i + 1 < mangled.size()) {
            if (mangled[i+1] == 'A') { result += "bool"; i += 2; }
            else if (mangled[i+1] == 'D') { result += "__int64"; i += 2; }
            else if (mangled[i+1] == 'E') { result += "unsigned __int64"; i += 2; }
            else if (mangled[i+1] == 'F') { result += "__int32"; i += 2; }
            else if (mangled[i+1] == 'G') { result += "unsigned __int32"; i += 2; }
            else if (mangled[i+1] == 'H') { result += "__int16"; i += 2; }
            else if (mangled[i+1] == 'I') { result += "unsigned __int16"; i += 2; }
            else if (mangled[i+1] == 'J') { result += "__int8"; i += 2; }
            else if (mangled[i+1] == 'K') { result += "unsigned __int8"; i += 2; }
            else if (mangled[i+1] == 'L') { result += "__int128"; i += 2; }
            else if (mangled[i+1] == 'M') { result += "unsigned __int128"; i += 2; }
            else if (mangled[i+1] == 'N') { result += "bool[]"; i += 2; }
            else { result += mangled[i]; ++i; }
        } else if (mangled[i] == 'C') {
            ++i;
            if (i < mangled.size()) {
                switch (mangled[i]) {
                    case 'A': result += "char"; break;
                    case 'D': result += "char"; break;
                    case 'E': result += "signed char"; break;
                    case 'F': result += "unsigned char"; break;
                    case 'G': result += "signed char"; break;
                    case 'H': result += "unsigned char"; break;
                    case 'I': result += "char"; break;
                    case 'J': result += "unsigned char"; break;
                    case 'L': result += "wchar_t"; break;
                    case 'M': result += "unsigned wchar_t"; break;
                    case 'N': result += "__int64"; break;
                    case 'O': result += "unsigned __int64"; break;
                    case 'P': result += "__int32"; break;
                    case 'Q': result += "unsigned __int32"; break;
                    case 'R': result += "__int16"; break;
                    case 'S': result += "unsigned __int16"; break;
                    case 'T': result += "__int8"; break;
                    case 'U': result += "unsigned __int8"; break;
                    case 'V': result += "__int128"; break;
                    case 'W': result += "unsigned __int128"; break;
                    case 'X': result += "long"; break;
                    case 'Y': result += "unsigned long"; break;
                    case 'Z': result += "void"; break;
                    default: result += "C" + std::string(1, mangled[i]); break;
                }
                ++i;
            }
        } else if (mangled[i] == 'D') {
            ++i;
            if (i < mangled.size()) {
                switch (mangled[i]) {
                    case 'A': result += "void"; break;
                    case 'B': result += "unsigned long"; break;
                    case 'C': result += "unsigned char"; break;
                    case 'D': result += "__int64"; break;
                    case 'E': result += "unsigned __int64"; break;
                    case 'F': result += "__int32"; break;
                    case 'G': result += "unsigned __int32"; break;
                    case 'H': result += "__int16"; break;
                    case 'I': result += "unsigned __int16"; break;
                    case 'J': result += "__int8"; break;
                    case 'K': result += "unsigned __int8"; break;
                    case 'L': result += "__int128"; break;
                    case 'M': result += "unsigned __int128"; break;
                    case 'N': result += "bool"; break;
                    case 'O': result += "float"; break;
                    case 'P': result += "double"; break;
                    case 'Q': result += "long double"; break;
                    case 'R': result += "unsigned long"; break;
                    case 'S': result += "unsigned long"; break;
                    case 'T': result += "union"; break;
                    case 'U': result += "int"; break;
                    case 'V': result += "unsigned int"; break;
                    case 'W': result += "int"; break;
                    case 'X': result += "unsigned int"; break;
                    case 'Y': result += "float"; break;
                    case 'Z': result += "double"; break;
                    default: result += "D" + std::string(1, mangled[i]); break;
                }
                ++i;
            }
        } else if (mangled[i] == 'E') {
            result += "...";
            ++i;
        } else if (mangled[i] == 'F') {
            result += "()";
            ++i;
        } else if (mangled[i] == 'G') {
            result += "{";
            ++i;
        } else if (mangled[i] == 'H') {
            result += "__based(";
            ++i;
        } else if (mangled[i] == 'I') {
            result += "[]";
            ++i;
        } else if (mangled[i] == 'J') {
            result += "()";
            ++i;
        } else if (mangled[i] == 'M') {
            result += "int";
            ++i;
        } else if (mangled[i] == 'N') {
            result += "unsigned int";
            ++i;
        } else if (mangled[i] == 'O') {
            result += "long";
            ++i;
        } else if (mangled[i] == 'P') {
            result += "*";
            ++i;
        } else if (mangled[i] == 'Q') {
            result += "*";
            ++i;
        } else if (mangled[i] == 'R') {
            result += "&";
            ++i;
        } else if (mangled[i] == 'S') {
            result += "unsigned short";
            ++i;
        } else if (mangled[i] == 'T') {
            result += "unsigned __int64";
            ++i;
        } else if (mangled[i] == 'U') {
            result += "struct ";
            ++i;
        } else if (mangled[i] == 'V') {
            result += "union ";
            ++i;
        } else if (mangled[i] == 'X') {
            result += "void";
            ++i;
        } else if (mangled[i] == 'Y') {
            result += "void";
            ++i;
        } else if (mangled[i] == 'Z') {
            result += "void";
            ++i;
        } else {
            result += mangled[i];
            ++i;
        }
    }

    return result.empty() ? "" : result;
}

bool MicrosoftDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling MSVC C++ symbols...");

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

    if (monitor) monitor->setMessage("Demangled " + std::to_string(count) + " MSVC symbols.");
    return true;
}

} // namespace ghidra
