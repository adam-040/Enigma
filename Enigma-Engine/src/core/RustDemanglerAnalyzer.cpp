#include <ghidra/RustDemanglerAnalyzer.h>
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
#include <sstream>
#include <cstdlib>

namespace ghidra {

RustDemanglerAnalyzer::RustDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Rust Demangler", "Demangles Rust symbols (v0 and legacy).") {
}

bool RustDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

namespace {

// Parse a base-62 digit: 0-9 a-z A-Z
static int base62Val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 36;
    return -1;
}

// Decode a base-62 integer from the mangled string
// Returns the value and advances the position
static uint64_t parseBase62(const std::string& s, size_t& pos) {
    uint64_t val = 0;
    while (pos < s.size()) {
        int d = base62Val(s[pos]);
        if (d < 0) break;
        val = val * 62 + static_cast<uint64_t>(d);
        ++pos;
    }
    return val;
}

// Demangle a Rust v0 symbol (_R...)
// RFC 2603: https://github.com/rust-lang/rfcs/blob/master/text/2603-rust-symbol-name-mangling-v0.md
static std::string demangleV0(const std::string& mangled) {
    // Format: _R + <path> [<instantiating-crate>] [<type>...]
    if (mangled.size() < 3 || mangled[0] != '_' || mangled[1] != 'R') return "";
    size_t i = 2;

    // Optional base-62 disambiguator followed by path
    // Path starts with a tag:
    // C = crate root, M = unnamed constant, N = nested path, s = suffix
    std::string result;
    while (i < mangled.size()) {
        char tag = mangled[i];
        if (tag == 'C') {
            // Crate root: skip optional disambiguator, then identifier
            ++i;
            // Optional base-62 disambiguator
            if (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                // This is ambiguous: base62 or length digit?
                // In v0, after 'C', there may be a base-62 disambiguator + '_', or just a length+identifier
                // The 'C' tag is followed by an optional base-62 _punctuated_ disambiguator
                // then by a normal identifier (length-prefixed)
                // Actually let's check: C<base62>_<identifier>
                size_t saved = i;
                while (i < mangled.size() && mangled[i] != '_' && mangled[i] >= '0' && mangled[i] <= '9') ++i;
                if (i < mangled.size() && mangled[i] == '_') {
                    // Disambiguator present, skip past '_'
                    ++i;
                } else {
                    // No disambiguator, restore position
                    i = saved;
                }
            }
            // Now parse identifier: <decimal-length><bytes>
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (len > 0 && i + len <= mangled.size()) {
                if (!result.empty() && result.back() != ' ' && result.back() != '(') result += "::";
                result += mangled.substr(i, len);
                i += len;
            }
        } else if (tag == 'N') {
            // Nested path: N<path><path>...
            // Skip 'N', parse sub-path
            ++i;
            // The nested path ends with 'E' or continues
            // Parse until we hit 'E' or another path tag
            while (i < mangled.size() && mangled[i] != 'E') {
                char subTag = mangled[i];
                if (subTag == 'C' || subTag == 'N' || subTag == 'M' || subTag == 's') {
                    // Recursively handle but for simplicity just break the loop
                    break;
                }
                // It's an identifier directly (length-prefixed)
                size_t len = 0;
                while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                    len = len * 10 + (mangled[i] - '0');
                    ++i;
                }
                if (len > 0 && i + len <= mangled.size()) {
                    if (!result.empty() && result.back() != ' ' && result.back() != '(' && result.back() != ':') result += "::";
                    result += mangled.substr(i, len);
                    i += len;
                } else break;
            }
            if (i < mangled.size() && mangled[i] == 'E') ++i;
        } else if (tag == 'M') {
            // Unnamed constant (impl): M<base62>
            ++i;
            std::stringstream ss;
            ss << parseBase62(mangled, i);
            if (!result.empty()) result += "::";
            result += "impl$" + ss.str();
        } else if (tag == 's') {
            // Suffix: 's' + <identifier>
            ++i;
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (len > 0 && i + len <= mangled.size()) {
                if (!result.empty() && result.back() != ' ' && result.back() != '(') result += "::";
                result += mangled.substr(i, len);
                i += len;
            }
        } else if (tag >= '0' && tag <= '9') {
            // Identifier directly at this level (no path tag)
            size_t len = 0;
            while (i < mangled.size() && mangled[i] >= '0' && mangled[i] <= '9') {
                len = len * 10 + (mangled[i] - '0');
                ++i;
            }
            if (len > 0 && i + len <= mangled.size()) {
                if (!result.empty() && result.back() != ' ' && result.back() != '(' && result.back() != ':') result += "::";
                result += mangled.substr(i, len);
                i += len;
            }
        } else if (tag == 'E') {
            ++i;
            break;
        } else {
            // Unknown tag or end of path — stop
            break;
        }
    }

    return result.empty() ? "" : result;
}

// Legacy Rust mangling (_RNv, _RNC, etc.)
static std::string demangleLegacy(const std::string& mangled) {
    if (mangled.size() < 4) return "";

    size_t start = 0;
    if (mangled.compare(0, 4, "_RNC") == 0 || mangled.compare(0, 4, "_RNv") == 0 ||
        mangled.compare(0, 4, "_RNc") == 0 || mangled.compare(0, 4, "_RNs") == 0 ||
        mangled.compare(0, 4, "_RNm") == 0 || mangled.compare(0, 4, "_RNb") == 0 ||
        mangled.compare(0, 4, "_RNF") == 0 || mangled.compare(0, 4, "_RNt") == 0) {
        start = 4;
    } else if (mangled.compare(0, 2, "_R") == 0) {
        // Could be v0 already handled, or legacy without path tag
        return "";
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

static std::string demangleRust(const std::string& mangled) {
    if (mangled.empty()) return "";

    // Try CLI: rustfilt if available
    // (deferred — requires subprocess, would slow down analysis)

    // Try v0 demangling first
    if (mangled.size() >= 3 && mangled[0] == '_' && mangled[1] == 'R') {
        std::string v0 = demangleV0(mangled);
        if (!v0.empty()) return v0;
    }

    // Fall back to legacy
    return demangleLegacy(mangled);
}

} // anonymous namespace

bool RustDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Demangling Rust symbols...");

    auto* symTable = program->getSymbolTable();
    if (!symTable) return false;

    auto it = symTable->getAllProgramSymbols(false);
    NamingService naming(program);
    int count = 0;
    while (it.hasNext()) {
        Symbol* sym = it.next();
        if (monitor && monitor->isCancelled()) break;
        std::string name = sym->getName();
        if (name.size() >= 2 && name[0] == '_' && name[1] == 'R') {
            std::string demangled = demangleRust(name);
            if (!demangled.empty()) {
                naming.assignAlias(sym->getAddress().getOffset(), demangled, SourceType::ANALYSIS);
                ++count;
            }
        }
    }

    Msg::info(getName(), "Demangled " + std::to_string(count) + " Rust symbols.");
    return true;
}

} // namespace ghidra