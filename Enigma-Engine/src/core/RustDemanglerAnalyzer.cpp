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
#include <algorithm>
#include <functional>

namespace ghidra {

RustDemanglerAnalyzer::RustDemanglerAnalyzer()
    : AbstractDemanglerAnalyzer("Rust Demangler", "Demangles Rust symbols (v0 and legacy).") {
}

bool RustDemanglerAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return true;
}

namespace {

static int base62Val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'z') return c - 'a' + 10;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 36;
    return -1;
}

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

static size_t parseDecimal(const std::string& s, size_t& pos) {
    size_t val = 0;
    while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
        val = val * 10 + (s[pos] - '0');
        ++pos;
    }
    return val;
}

static std::string decodePunycode(const std::string& label) {
    size_t lastHyphen = label.rfind('-');
    std::string basic;
    std::string encoded;
    if (lastHyphen != std::string::npos && lastHyphen > 0) {
        basic = label.substr(0, lastHyphen);
        encoded = label.substr(lastHyphen + 1);
    } else {
        encoded = label;
    }

    std::vector<uint32_t> codepoints;
    for (char c : basic) codepoints.push_back(static_cast<uint32_t>(c));

    if (encoded.empty()) {
        std::string result;
        for (uint32_t cp : codepoints) {
            if (cp < 0x80) result += static_cast<char>(cp);
            else if (cp < 0x800) { result += static_cast<char>(0xC0|(cp>>6)); result += static_cast<char>(0x80|(cp&0x3F)); }
            else { result += static_cast<char>(0xE0|(cp>>12)); result += static_cast<char>(0x80|((cp>>6)&0x3F)); result += static_cast<char>(0x80|(cp&0x3F)); }
        }
        return result;
    }

    const uint32_t base = 36, tmin = 1, tmax = 26, skew = 38, initialBias = 72, initialN = 128;
    uint32_t n = initialN, i = 0, bias = initialBias;
    size_t pos = 0;

    while (pos < encoded.size()) {
        uint32_t delta = 0, w = 1, k;
        for (k = 0; ; k++) {
            if (pos >= encoded.size()) break;
            uint32_t digit = static_cast<uint32_t>(base62Val(encoded[pos]));
            if (digit == static_cast<uint32_t>(-1)) break;
            ++pos;
            delta += digit * w;
            uint32_t t = (k <= bias) ? tmin : (k >= bias + tmax ? tmax : k - bias);
            if (digit < t) break;
            w *= (base - t);
        }
        uint32_t len = static_cast<uint32_t>(codepoints.size()) + 1;
        bias = (delta == 0) ? 0 : initialBias + (36 * delta / (delta + skew));

        uint32_t q = delta, si = 0;
        for (uint32_t j = len; ; j++) {
            uint32_t t2 = (j <= bias) ? tmin : (j >= bias + tmax ? tmax : j - bias);
            if (q < t2) break;
            codepoints.insert(codepoints.begin() + si, n);
            ++si;
            q = (q - t2) / (base - t2);
        }
        n += q;
    }

    std::string result;
    for (uint32_t cp : codepoints) {
        if (cp < 0x80) result += static_cast<char>(cp);
        else if (cp < 0x800) { result += static_cast<char>(0xC0|(cp>>6)); result += static_cast<char>(0x80|(cp&0x3F)); }
        else { result += static_cast<char>(0xE0|(cp>>12)); result += static_cast<char>(0x80|((cp>>6)&0x3F)); result += static_cast<char>(0x80|(cp&0x3F)); }
    }
    return result;
}

static std::string decodePunycodeInString(const std::string& input) {
    std::string result = input;
    size_t pos = 0;
    while (pos < result.size()) {
        size_t xnPos = result.find("xn--", pos);
        if (xnPos == std::string::npos) xnPos = result.find("XN--", pos);
        if (xnPos == std::string::npos) break;
        size_t labelEnd = result.find("::", xnPos);
        if (labelEnd == std::string::npos) labelEnd = result.size();
        std::string label = result.substr(xnPos, labelEnd - xnPos);
        std::string decoded = decodePunycode(label);
        result.replace(xnPos, label.size(), decoded);
        pos = xnPos + decoded.size();
    }
    return result;
}

static std::string demangleV0(const std::string& mangled) {
    if (mangled.size() < 3 || mangled[0] != '_' || mangled[1] != 'R') return "";
    size_t i = 2;

    auto parseIdent = [&](size_t& pos) -> std::string {
        size_t len = parseDecimal(mangled, pos);
        if (len > 0 && pos + len <= mangled.size()) {
            std::string ident = mangled.substr(pos, len);
            pos += len;
            return ident;
        }
        return "";
    };

    // Skip type string at end (after path) - we only want the path part
    std::function<std::string(size_t&)> parsePath;

    parsePath = [&](size_t& pos) -> std::string {
        if (pos >= mangled.size()) return "";
        char tag = mangled[pos];
        std::string path;

        if (tag == 'C') {
            ++pos;
            if (pos < mangled.size() && mangled[pos] >= '0' && mangled[pos] <= '9') {
                size_t saved = pos;
                while (pos < mangled.size() && mangled[pos] != '_' &&
                       mangled[pos] >= '0' && mangled[pos] <= '9') ++pos;
                if (pos < mangled.size() && mangled[pos] == '_') ++pos;
                else pos = saved;
            }
            path = parseIdent(pos);
        } else if (tag == 'N') {
            ++pos;
            std::string ns = parseIdent(pos);
            if (!ns.empty()) path = ns;
            while (pos < mangled.size() && mangled[pos] != 'E') {
                char subTag = mangled[pos];
                if (subTag == 'C' || subTag == 'N' || subTag == 'M') {
                    std::string sub = parsePath(pos);
                    if (!sub.empty()) path += "::" + sub;
                } else if (subTag == 'B') {
                    ++pos;
                    if (pos < mangled.size() && mangled[pos] >= '0' && mangled[pos] <= '9')
                        parseIdent(pos);
                    else if (pos < mangled.size() && mangled[pos] == 'p') ++pos;
                    std::string sub = parsePath(pos);
                    if (!sub.empty()) path += "::" + sub;
                } else if (subTag >= '0' && subTag <= '9') {
                    std::string sub = parseIdent(pos);
                    if (!sub.empty()) path += "::" + sub;
                } else if (subTag == 'I' || subTag == 'K') {
                    ++pos;
                    while (pos < mangled.size() && mangled[pos] != 'E') ++pos;
                    if (pos < mangled.size()) ++pos;
                } else if (subTag == 'X' || subTag == 'Y') {
                    ++pos;
                    while (pos < mangled.size() && mangled[pos] != 'E') ++pos;
                    if (pos < mangled.size()) ++pos;
                } else {
                    break;
                }
            }
            if (pos < mangled.size() && mangled[pos] == 'E') ++pos;
        } else if (tag == 'M') {
            ++pos;
            std::stringstream ss;
            ss << parseBase62(mangled, pos);
            path = "impl$" + ss.str();
        } else if (tag == 'I' || tag == 'K') {
            ++pos;
            path = "impl";
            while (pos < mangled.size() && mangled[pos] != 'E') ++pos;
            if (pos < mangled.size()) ++pos;
        } else if (tag == 's') {
            ++pos;
            path = parseIdent(pos);
        } else if (tag == 'B') {
            ++pos;
            if (pos < mangled.size() && mangled[pos] >= '0' && mangled[pos] <= '9')
                parseIdent(pos);
            else if (pos < mangled.size() && mangled[pos] == 'p') ++pos;
            path = parsePath(pos);
        } else if (tag >= '0' && tag <= '9') {
            path = parseIdent(pos);
        } else {
            ++pos;
        }
        return path;
    };

    std::string result = parsePath(i);
    if (result.empty()) return "";

    // Apply Punycode decoding
    if (result.find("xn--") != std::string::npos || result.find("XN--") != std::string::npos) {
        result = decodePunycodeInString(result);
    }

    return result;
}

static std::string demangleLegacy(const std::string& mangled) {
    if (mangled.size() < 4) return "";

    size_t start = 0;
    if (mangled.compare(0, 4, "_RNC") == 0 || mangled.compare(0, 4, "_RNv") == 0 ||
        mangled.compare(0, 4, "_RNc") == 0 || mangled.compare(0, 4, "_RNs") == 0 ||
        mangled.compare(0, 4, "_RNm") == 0 || mangled.compare(0, 4, "_RNb") == 0 ||
        mangled.compare(0, 4, "_RNF") == 0 || mangled.compare(0, 4, "_RNt") == 0) {
        start = 4;
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
    if (mangled.size() >= 3 && mangled[0] == '_' && mangled[1] == 'R') {
        std::string v0 = demangleV0(mangled);
        if (!v0.empty()) return v0;
    }
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
