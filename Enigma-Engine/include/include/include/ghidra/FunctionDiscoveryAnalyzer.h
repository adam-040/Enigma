#pragma once

#include <ghidra/Address.h>
#include <ghidra/BinaryLoader.h>
#include <ghidra/SourceType.h>
#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

class AddressSpace;
class FunctionManager;

enum class FunctionCandidateKind {
    ENTRY,
    EXPORT,
    SYMBOL,
    CALL_TARGET,
    IMPORT,
    THUNK
};

struct FunctionCandidate {
    uint64_t address = 0;
    std::string name;
    FunctionCandidateKind kind = FunctionCandidateKind::CALL_TARGET;
    SourceType source = SourceType::ANALYSIS;
    bool external = false;
    bool thunk = false;
    std::string libraryName;
    std::string reason;
};

struct FunctionDiscoveryOptions {
    bool includeEntryPoint = true;
    bool includeExports = true;
    bool includeSymbols = true;
    bool includeImports = true;
    bool includeExternalInFunctionManager = false;
    uint64_t defaultBodySize = 1;
};

struct FunctionDiscoveryResult {
    std::vector<FunctionCandidate> candidates;
    int createdFunctions = 0;
    int skippedExisting = 0;
    int skippedExternal = 0;
    int failedCreates = 0;
};

class FunctionDiscoveryAnalyzer {
public:
    explicit FunctionDiscoveryAnalyzer(FunctionDiscoveryOptions options = {});

    void clear();
    void analyzeLoader(const BinaryLoader& loader);
    void addCallTarget(uint64_t address, const std::string& name = {});
    void addCandidate(FunctionCandidate candidate);

    const std::vector<FunctionCandidate>& getCandidates() const { return candidates_; }
    FunctionDiscoveryResult getResult() const;

    FunctionDiscoveryResult applyTo(FunctionManager& manager, AddressSpace* codeSpace) const;

    static std::string defaultFunctionName(uint64_t address);
    static const char* kindToString(FunctionCandidateKind kind);

private:
    FunctionDiscoveryOptions options_;
    std::vector<FunctionCandidate> candidates_;

    int findCandidate(uint64_t address) const;
    static int priority(FunctionCandidateKind kind);
    static bool isBetter(const FunctionCandidate& lhs, const FunctionCandidate& rhs);
    static std::string sanitizeName(const std::string& name, uint64_t fallbackAddress);
};

} // namespace ghidra
