#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/AutoNaming.h>
#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace ghidra {

namespace {

int priority(FunctionCandidateKind kind) {
    switch (kind) {
        case FunctionCandidateKind::ENTRY: return 100;
        case FunctionCandidateKind::EXPORT: return 90;
        case FunctionCandidateKind::SYMBOL: return 80;
        case FunctionCandidateKind::CALL_TARGET: return 60;
        case FunctionCandidateKind::THUNK: return 40;
        case FunctionCandidateKind::IMPORT: return 30;
    }
    return 0;
}

std::string sanitizeName(std::string name) {
    if (name.empty())
        return name;

    for (char& c : name) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '_')
            c = '_';
    }
    unsigned char first = static_cast<unsigned char>(name.front());
    if (!std::isalpha(first) && name.front() != '_')
        name.insert(name.begin(), '_');
    return name;
}

} // namespace

FunctionDiscoveryAnalyzer::FunctionDiscoveryAnalyzer(FunctionDiscoveryOptions options)
    : options_(options) {}

void FunctionDiscoveryAnalyzer::clear() {
    candidates_.clear();
}

void FunctionDiscoveryAnalyzer::analyzeLoader(const BinaryLoader& loader) {
    // Pre-compute executable section ranges for validity checking.
    // When sections are available, skip candidates outside executable regions
    // (e.g., IAT entries in .rdata for PE). Raw binaries without sections pass through.
    auto sections = loader.getSections();
    auto isInExecSection = [&sections](uint64_t addr) -> bool {
        if (sections.empty()) return true;
        for (const auto& sec : sections) {
            if (!sec.isExecutable) continue;
            uint64_t secEnd = sec.virtualAddress + std::max(sec.virtualSize, sec.fileSize);
            if (addr >= sec.virtualAddress && addr < secEnd)
                return true;
        }
        return false;
    };

    if (options_.includeEntryPoint && loader.getEntryPoint() != 0) {
        FunctionCandidate candidate;
        candidate.address = loader.getEntryPoint();
        candidate.name = "entry";
        candidate.kind = FunctionCandidateKind::ENTRY;
        candidate.source = SourceType::ANALYSIS;
        candidate.reason = "loader entry point";
        addCandidate(candidate);
    }

    if (options_.includeExports) {
        for (const auto& exp : loader.getExports()) {
            if (exp.address == 0)
                continue;
            if (!isInExecSection(exp.address)) continue;
            FunctionCandidate candidate;
            candidate.address = exp.address;
            candidate.name = exp.name.empty() ? defaultFunctionName(exp.address) : exp.name;
            candidate.kind = FunctionCandidateKind::EXPORT;
            candidate.source = SourceType::IMPORTED;
            candidate.reason = "loader export";
            addCandidate(candidate);
        }
    }

    if (options_.includeSymbols) {
        for (const auto& sym : loader.getSymbols()) {
            if (!sym.isFunction || sym.address == 0)
                continue;
            if (!isInExecSection(sym.address)) continue;
            FunctionCandidate candidate;
            candidate.address = sym.address;
            candidate.name = sym.name.empty() ? defaultFunctionName(sym.address) : sym.name;
            candidate.kind = FunctionCandidateKind::SYMBOL;
            candidate.source = sym.isExternal ? SourceType::IMPORTED : SourceType::ANALYSIS;
            candidate.external = sym.isExternal;
            candidate.reason = "loader function symbol";
            addCandidate(candidate);
        }
    }

    if (options_.includeImports) {
        for (const auto& imp : loader.getImports()) {
            if (imp.address == 0)
                continue;
            if (!isInExecSection(imp.address)) continue;
            FunctionCandidate candidate;
            candidate.address = imp.address;
            candidate.name = imp.functionName.empty() ? defaultFunctionName(imp.address) : imp.functionName;
            candidate.kind = FunctionCandidateKind::IMPORT;
            candidate.source = SourceType::IMPORTED;
            candidate.external = true;
            candidate.thunk = true;
            candidate.libraryName = imp.libraryName;
            candidate.reason = "loader import";
            addCandidate(candidate);
        }
    }
}

void FunctionDiscoveryAnalyzer::addCallTarget(uint64_t address, const std::string& name) {
    if (address == 0)
        return;
    FunctionCandidate candidate;
    candidate.address = address;
    candidate.name = name.empty() ? defaultFunctionName(address) : name;
    candidate.kind = FunctionCandidateKind::CALL_TARGET;
    candidate.source = SourceType::ANALYSIS;
    candidate.reason = "direct call target";
    addCandidate(candidate);
}

void FunctionDiscoveryAnalyzer::addCandidate(FunctionCandidate candidate) {
    if (candidate.address == 0)
        return;
    if (candidate.name.empty())
        candidate.name = defaultFunctionName(candidate.address);
    candidate.name = sanitizeName(candidate.name, candidate.address);

    auto it = std::find_if(candidates_.begin(), candidates_.end(),
                           [&](const FunctionCandidate& existing) {
                               return existing.address == candidate.address;
                           });
    if (it == candidates_.end()) {
        candidates_.push_back(std::move(candidate));
        return;
    }

    if (priority(candidate.kind) > priority(it->kind))
        *it = std::move(candidate);
    else if (it->name.empty() || it->name == defaultFunctionName(it->address) ||
             it->name == "entry")
        it->name = candidate.name;
}

FunctionDiscoveryResult FunctionDiscoveryAnalyzer::getResult() const {
    FunctionDiscoveryResult result;
    result.candidates = candidates_;
    return result;
}

FunctionDiscoveryResult FunctionDiscoveryAnalyzer::applyTo(FunctionManager& manager,
                                                           AddressSpace* codeSpace) const {
    FunctionDiscoveryResult result;
    result.candidates = candidates_;
    if (codeSpace == nullptr)
        return result;

    uint64_t bodySize = std::max<uint64_t>(1, options_.defaultBodySize);
    for (const auto& candidate : candidates_) {
        if (candidate.external && !options_.includeExternalInFunctionManager) {
            ++result.skippedExternal;
            continue;
        }

        Address entry(codeSpace, static_cast<int64_t>(candidate.address));
        if (manager.getFunctionAt(entry) != nullptr) {
            ++result.skippedExisting;
            continue;
        }

        Address end = entry.add(static_cast<int64_t>(bodySize - 1));
        AddressSet body(entry, end);
        try {
            Function* func = manager.createFunction(candidate.name, entry, body, candidate.source);
            if (func != nullptr) {
                func->setExternal(candidate.external);
                func->setThunk(candidate.thunk);
                ++result.createdFunctions;
            } else {
                ++result.failedCreates;
            }
        } catch (...) {
            ++result.failedCreates;
        }
    }
    return result;
}

std::string FunctionDiscoveryAnalyzer::defaultFunctionName(uint64_t address) {
    std::ostringstream out;
    return AutoNaming::nameVal("func", address);
}

const char* FunctionDiscoveryAnalyzer::kindToString(FunctionCandidateKind kind) {
    switch (kind) {
        case FunctionCandidateKind::ENTRY: return "entry";
        case FunctionCandidateKind::EXPORT: return "export";
        case FunctionCandidateKind::SYMBOL: return "symbol";
        case FunctionCandidateKind::CALL_TARGET: return "call_target";
        case FunctionCandidateKind::IMPORT: return "import";
        case FunctionCandidateKind::THUNK: return "thunk";
    }
    return "unknown";
}

int FunctionDiscoveryAnalyzer::findCandidate(uint64_t address) const {
    for (size_t i = 0; i < candidates_.size(); ++i) {
        if (candidates_[i].address == address)
            return static_cast<int>(i);
    }
    return -1;
}

int FunctionDiscoveryAnalyzer::priority(FunctionCandidateKind kind) {
    switch (kind) {
        case FunctionCandidateKind::ENTRY: return 100;
        case FunctionCandidateKind::EXPORT: return 90;
        case FunctionCandidateKind::SYMBOL: return 80;
        case FunctionCandidateKind::CALL_TARGET: return 60;
        case FunctionCandidateKind::THUNK: return 40;
        case FunctionCandidateKind::IMPORT: return 30;
    }
    return 0;
}

bool FunctionDiscoveryAnalyzer::isBetter(const FunctionCandidate& lhs,
                                         const FunctionCandidate& rhs) {
    return priority(lhs.kind) > priority(rhs.kind);
}

std::string FunctionDiscoveryAnalyzer::sanitizeName(const std::string& name,
                                                    uint64_t fallbackAddress) {
    std::string result = name.empty() ? defaultFunctionName(fallbackAddress) : name;
    for (char& c : result) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!std::isalnum(uc) && c != '_')
            c = '_';
    }
    unsigned char first = static_cast<unsigned char>(result.front());
    if (!std::isalpha(first) && result.front() != '_')
        result.insert(result.begin(), '_');
    return result;
}

} // namespace ghidra
