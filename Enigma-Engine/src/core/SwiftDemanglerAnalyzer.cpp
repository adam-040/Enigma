#include <ghidra/SwiftDemanglerAnalyzer.h>
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
#include <cstdio>
#include <memory>

namespace ghidra {

SwiftDemanglerAnalyzer::SwiftDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Swift Demangler", "Demangles Swift symbols (built-in + swift demangle tool).") {
}

bool SwiftDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

namespace {

// Try to demangle using the `swift demangle` command-line tool
static std::string demangleViaTool(const std::string& mangled) {
#if defined(_WIN32)
    std::string cmd = "swift demangle \"" + mangled + "\" 2>nul";
#else
    std::string cmd = "swift demangle \"" + mangled + "\" 2>/dev/null";
#endif
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    std::string result;
    char buffer[4096];
    size_t totalRead = 0;
    while (fgets(buffer, sizeof(buffer), pipe) && totalRead < sizeof(buffer)) {
        result += buffer;
        totalRead += strlen(buffer);
    }
    pclose(pipe);

    // Clean up output: swift demangle returns "mangled ---> demangled"
    size_t arrow = result.find("--->");
    if (arrow != std::string::npos) {
        result = result.substr(arrow + 5);
        // Trim whitespace
        while (!result.empty() && (result.back() == '\n' || result.back() == '\r' || result.back() == ' '))
            result.pop_back();
        while (!result.empty() && (result[0] == ' ' || result[0] == '\t'))
            result.erase(0, 1);
        return result;
    }
    return "";
}

// Built-in basic Swift demangler (handles simple cases when swift tool is unavailable)
static std::string demangleSwiftBuiltin(const std::string& mangled) {
    if (mangled.empty()) return "";

    size_t start = 0;
    if (mangled.compare(0, 3, "_$s") == 0) {
        start = 3;
    } else if (mangled.compare(0, 2, "_T") == 0) {
        start = 2;
    } else if (mangled.compare(0, 2, "$S") == 0) {
        start = 2;
    } else if (mangled.compare(0, 3, "_$S") == 0) {
        start = 3;
    } else {
        return "";
    }

    std::string result;
    size_t i = start;
    while (i < mangled.size()) {
        if (mangled[i] == 's') {
            if (!result.empty() && result.back() != '.' && result.back() != '(') result += ".";
            result += "Swift";
            ++i;
        } else if (mangled[i] == 'S') {
            if (!result.empty() && result.back() != '.' && result.back() != '(') result += ".";
            result += "Swift.";
            ++i;
        } else if (mangled[i] >= '0' && mangled[i] <= '9') {
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (!result.empty() && result.back() != '.' && result.back() != '(') result += ".";
            if (len > 0 && i + len <= mangled.size()) {
                result += mangled.substr(i, len);
                i += len;
            }
        } else if (mangled[i] == 'y') {
            result += " -> ";
            ++i;
        } else if (mangled[i] == 'F') {
            result += "()";
            ++i;
        } else if (mangled[i] == 'o') {
            result += " -> ";
            ++i;
        } else if (mangled[i] == 'f') {
            result += " -> ";
            ++i;
        } else if (mangled[i] == 'x' || mangled[i] == 'X') {
            ++i;
        } else if (mangled[i] == 'z') {
            result += "(";
            ++i;
            while (i < mangled.size() && mangled[i] != 'z') {
                if (mangled[i] >= '0' && mangled[i] <= '9') {
                    size_t len = 0;
                    while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                        len = len * 10 + (mangled[i] - '0');
                        ++i;
                    }
                    if (len > 0 && i + len <= mangled.size()) {
                        result += mangled.substr(i, len);
                        i += len;
                    }
                } else {
                    result += mangled[i];
                    ++i;
                }
            }
            if (i < mangled.size() && mangled[i] == 'z') {
                result += ")";
                ++i;
            }
        } else if (mangled[i] == 'V') {
            if (!result.empty() && result.back() != '.') result += ".";
            result += "(value)";
            ++i;
        } else if (mangled[i] == 'O') {
            if (!result.empty() && result.back() != '.') result += ".";
            result += "(enum)";
            ++i;
        } else if (mangled[i] == 'C') {
            if (!result.empty() && result.back() != '.') result += ".";
            result += "(class)";
            ++i;
        } else if (mangled[i] == 'P') {
            if (!result.empty() && result.back() != '.') result += ".";
            result += "(protocol)";
            ++i;
        } else {
            ++i;
        }
    }

    return result.empty() ? "" : result;
}

static std::string demangleSwift(const std::string& mangled) {
    // Try swift demangle tool first
    std::string toolResult = demangleViaTool(mangled);
    if (!toolResult.empty()) return toolResult;

    // Fall back to built-in
    return demangleSwiftBuiltin(mangled);
}

} // anonymous namespace

bool SwiftDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling Swift symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    NamingService naming(program);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 2 &&
            ((name[0] == '_' && (name.compare(0, 3, "_$s") == 0 || name.compare(0, 2, "_T") == 0 ||
              name.compare(0, 3, "_$S") == 0)) ||
             (name[0] == '$' && name.size() >= 2 && name[1] == 'S'))) {
            std::string demangled = demangleSwift(name);
            if (!demangled.empty()) {
                naming.assignAlias(sym->getAddress().getOffset(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    Msg::info(getName(), "Demangled " + std::to_string(count) + " Swift symbols.");
    return true;
}

} // namespace ghidra