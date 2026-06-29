/* ###
 * IP: GHIDRA
 *
 * FksLibrary — FlatBuffer serialization / deserialization for .fkslib files.
 */
#include <ghidra/FksLibrary.h>
#include <flatbuffers/flatbuffers.h>
#include "fks_generated.h"
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <ctime>

namespace ghidra {

namespace fb = fbschema;
namespace fs = std::filesystem;

// ── LE uint64 helpers (matching IndexManager pattern) ────────────────────────

static void putU64LE(uint8_t* buf, uint64_t val) {
    for (int i = 0; i < 8; i++) { buf[i] = static_cast<uint8_t>(val & 0xFF); val >>= 8; }
}

static uint64_t getU64LE(const uint8_t* buf) {
    uint64_t val = 0;
    for (int i = 7; i >= 0; i--) { val <<= 8; val |= buf[i]; }
    return val;
}

// ── Load from FlatBuffer ─────────────────────────────────────────────────────

std::unique_ptr<FksLibrary> FksLibrary::loadFromFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in.is_open()) throw std::runtime_error("FksLibrary: cannot open " + path);

    size_t size = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    in.read(reinterpret_cast<char*>(buf.data()), size);
    if (!in) throw std::runtime_error("FksLibrary: read failed " + path);

    return loadFromBuffer(buf.data(), buf.size());
}

std::unique_ptr<FksLibrary> FksLibrary::loadFromBuffer(const uint8_t* data, size_t size) {
    flatbuffers::Verifier verifier(data, size);
    if (!verifier.VerifyBuffer<fb::FksLibrary>(nullptr))
        throw std::runtime_error("FksLibrary: verification failed (corrupt data)");

    auto root = flatbuffers::GetRoot<fb::FksLibrary>(data);

    auto lib = std::make_unique<FksLibrary>();

    // Schema version check (v2 = old fields only, v3 = new fields appended)
    if (root->schema_version() < 1 || root->schema_version() > 3)
        throw std::runtime_error("FksLibrary: unsupported schema version");

    // Meta
    if (auto* meta = root->meta()) {
        FksLibraryMeta m;
        m.family      = meta->family()      ? meta->family()->str()      : "";
        m.version     = meta->version()     ? meta->version()->str()     : "";
        m.variant     = meta->variant()     ? meta->variant()->str()     : "";
        m.compiler    = meta->compiler()    ? meta->compiler()->str()    : "";
        m.language    = meta->language()    ? meta->language()->str()    : "";
        m.description = meta->description() ? meta->description()->str() : "";
        m.created     = meta->created();
        lib->setMeta(m);
    }

    // Functions
    if (auto* funcs = root->functions()) {
        lib->functions_.reserve(funcs->size());
        for (auto* fbFunc : *funcs) {
            FksFunction f;
            f.uid         = fbFunc->uid();
            f.name        = fbFunc->name()        ? fbFunc->name()->str()        : "";
            f.nameDemangled = fbFunc->name_demangled() ? fbFunc->name_demangled()->str() : "";
            f.namespacePath = fbFunc->namespace_path() ? fbFunc->namespace_path()->str() : "";
            if (auto* h = fbFunc->hashes()) {
                f.hashes.fullHash  = h->full_hash();
                f.hashes.shortHash = h->short_hash();
                f.hashes.mnemHash  = h->mnem_hash();
                f.hashes.callHash  = h->call_hash();
            }
            if (auto* h2 = fbFunc->hashes_v2()) {
                f.hashesV2.fullHash  = h2->full_hash();
                f.hashesV2.shortHash = h2->short_hash();
                f.hashesV2.mnemHash  = h2->mnem_hash();
                f.hashesV2.callHash  = h2->call_hash();
            }
            f.bodySize    = fbFunc->body_size();
            f.instrCount  = fbFunc->instr_count();
            f.callCount   = fbFunc->call_count();
            f.basicBlocks = fbFunc->basic_blocks();
            f.cyclomatic  = fbFunc->cyclomatic();
            f.hasFrame    = fbFunc->has_frame();
            f.isThunk     = fbFunc->is_thunk();
            f.isLibrary   = fbFunc->is_library();
            f.isExternal  = fbFunc->is_external();
            f.signature   = fbFunc->signature() ? fbFunc->signature()->str() : "";
            f.exported    = fbFunc->exported();
            f.virtualAddress = fbFunc->virtual_address();
            lib->functions_.push_back(std::move(f));
        }
    }

    // Relations
    if (auto* rels = root->relations()) {
        lib->relations_.reserve(rels->size());
        for (auto* r : *rels) {
            lib->relations_.push_back({r->caller_index(), r->callee_index()});
        }
    }

    return lib;
}

// ── Save to FlatBuffer ───────────────────────────────────────────────────────

bool FksLibrary::saveToFile(const std::string& path) {
    flatbuffers::FlatBufferBuilder builder(1024 * 1024);

    // Build meta
    auto fbMeta = fb::CreateFksLibraryMetaDirect(
        builder,
        meta_.family.c_str(),
        meta_.version.c_str(),
        meta_.variant.c_str(),
        meta_.compiler.c_str(),
        meta_.language.c_str(),
        meta_.description.c_str(),
        meta_.created);

    // Build functions
    std::vector<flatbuffers::Offset<fb::FksFunction>> fbFuncs;
    fbFuncs.reserve(functions_.size());
    for (auto& f : functions_) {
        auto nameStr = builder.CreateString(f.name);
        auto demStr  = builder.CreateString(f.nameDemangled);
        auto nsStr   = builder.CreateString(f.namespacePath);
        auto sigStr  = builder.CreateString(f.signature);
        auto fbHash  = fb::FkHashQuad(f.hashes.fullHash, f.hashes.shortHash,
                                       f.hashes.mnemHash, f.hashes.callHash);
        auto fbHashV2 = fb::FkHashQuadV2(f.hashesV2.fullHash, f.hashesV2.shortHash,
                                          f.hashesV2.mnemHash, f.hashesV2.callHash);
        fbFuncs.push_back(fb::CreateFksFunction(
            builder, f.uid, nameStr, demStr, &fbHash, &fbHashV2,
            f.bodySize, f.instrCount, f.callCount, f.basicBlocks,
            f.cyclomatic, f.hasFrame, f.exported, f.virtualAddress,
            nsStr, f.isThunk, f.isLibrary, f.isExternal, sigStr));
    }
    auto fbFuncVec = builder.CreateVector(fbFuncs);

    // Build relations
    std::vector<flatbuffers::Offset<fb::FksRelation>> fbRels;
    fbRels.reserve(relations_.size());
    for (auto& r : relations_) {
        fbRels.push_back(fb::CreateFksRelation(builder, r.callerIndex, r.calleeIndex));
    }
    auto fbRelVec = builder.CreateVector(fbRels);

    // Build root
    auto root = fb::CreateFksLibrary(builder, 3, fbMeta, fbFuncVec, fbRelVec);
    builder.Finish(root);

    // Write to file
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize());
    return out.good();
}

} // namespace ghidra
