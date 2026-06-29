/* ###
 * IP: GHIDRA
 *
 * FksLibrary — authoritative function knowledge library.
 * Each FksLibrary represents one library family + compiler + architecture.
 * Serialized as a .fkslib FlatBuffer file.
 */
#pragma once

#include <ghidra/FunctionFingerprint.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdint>

namespace ghidra {

struct FkHashQuad {
    uint64_t fullHash  = 0;
    uint64_t shortHash = 0;
    uint64_t mnemHash  = 0;
    uint64_t callHash  = 0;
};

struct FkHashQuadV2 {
    uint64_t fullHash  = 0;  // Mnemonic opcode sequence hash
    uint64_t shortHash = 0;  // First 8 mnemonics hash
    uint64_t mnemHash  = 0;  // Mnemonic sequence without calls/jumps
    uint64_t callHash  = 0;  // First 4 bytes of each instruction
};

struct FksFunction {
    uint64_t uid         = 0;
    std::string name;
    std::string nameDemangled;
    std::string namespacePath;
    FkHashQuad hashes;       // V1: raw-byte hashes
    FkHashQuadV2 hashesV2;   // V2: instruction-aware hashes
    uint32_t bodySize    = 0;
    uint16_t instrCount  = 0;
    uint16_t callCount   = 0;
    uint16_t basicBlocks = 0;
    uint16_t cyclomatic   = 0;
    bool hasFrame        = false;
    bool isThunk         = false;
    bool isLibrary       = false;
    bool isExternal      = false;
    std::string signature;
    bool exported        = false;
    uint64_t virtualAddress = 0;  // Virtual address for address-based lookup
};

struct FksLibraryMeta {
    std::string family;
    std::string version;
    std::string variant;
    std::string compiler;
    std::string language;
    std::string description;
    uint64_t created      = 0;
};

struct FksRelation {
    uint32_t callerIndex  = 0;
    uint32_t calleeIndex  = 0;
};

// In-memory model for a FKS knowledge library.
class FksLibrary {
public:
    static std::unique_ptr<FksLibrary> loadFromFile(const std::string& path);
    static std::unique_ptr<FksLibrary> loadFromBuffer(const uint8_t* data, size_t size);

    bool saveToFile(const std::string& path);

    const FksLibraryMeta& getMeta() const { return meta_; }
    const std::vector<FksFunction>& getFunctions() const { return functions_; }
    const std::vector<FksRelation>& getRelations() const { return relations_; }

    void setMeta(const FksLibraryMeta& m) { meta_ = m; }
    void addFunction(const FksFunction& f) { functions_.push_back(f); }
    void addRelation(const FksRelation& r) { relations_.push_back(r); }

    void clear() { functions_.clear(); relations_.clear(); }
    int functionCount() const { return static_cast<int>(functions_.size()); }

private:
    FksLibraryMeta meta_;
    std::vector<FksFunction> functions_;
    std::vector<FksRelation> relations_;
};

} // namespace ghidra
