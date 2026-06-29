/// enigma_fingerprint_audit.cpp
/// Fingerprint V1 vs V2 quality comparison with prefix length sweep and body-size disambiguation.
///
/// Usage: enigma_fingerprint_audit <binary_a> <binary_b> [--csv output.csv]

#include <ghidra/BinaryLoader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/NamingService.h>
#include <ghidra/FNV1a64.h>
#include <ghidra/FunctionFingerprint.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/DataSectionFunctionScannerAnalyzer.h>
#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/FidAnalyzer.h>
#include <ghidra/FunctionBodyFinalizer.h>
#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/DataRefFunctionAnalyzer.h>
#include <ghidra/PEExceptionAnalyzer.h>
#include <ghidra/ImportThunkAnalyzer.h>
#include <ghidra/ScalarOperandAnalyzer.h>
#include <ghidra/OperandReferenceAnalyzer.h>
#include <ghidra/DataOperandReferenceAnalyzer.h>
#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/StackReferenceAnalyzer.h>
#include <ghidra/StackVariableAnalyzer.h>
#include <ghidra/TaskMonitor.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iomanip>

using namespace ghidra;

namespace {

// ── Data structures ─────────────────────────────────────────────────────────

struct FuncRecord {
    std::string name;
    uint64_t address;
    int bodySize;
    uint8_t rawBytes[32];
    int bytesCode;
    uint64_t v1FullHash;
    uint64_t v1ShortHash;
    std::string mnemonicSequence;  // full mnemonic sequence (comma-separated)
    int instrCount;
};

// ── Capstone disassembly for V2 ─────────────────────────────────────────────

bool isCallOrJump(const std::string& mn) {
    return mn == "call" || mn == "jmp" || mn == "je" || mn == "jne" ||
           mn == "jz" || mn == "jnz" || mn == "jg" || mn == "jge" ||
           mn == "jl" || mn == "jle" || mn == "ja" || mn == "jae" ||
           mn == "jb" || mn == "jbe" || mn == "jo" || mn == "jno" ||
           mn == "js" || mn == "jns" || mn == "jp" || mn == "jnp" ||
           mn == "loop" || mn == "loope" || mn == "loopne";
}

std::vector<std::string> disassembleMnemonics(Memory* memory, Address entry, int maxInstr) {
    std::vector<std::string> result;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return result;

    uint8_t codeBuf[64];
    int bytesRead = memory->getBytes(entry, codeBuf, sizeof(codeBuf));
    if (bytesRead < 1) { cs_close(&handle); return result; }

    cs_insn* insns = nullptr;
    size_t count = cs_disasm(handle, codeBuf, bytesRead,
                             entry.getOffset(), maxInstr, &insns);
    for (size_t i = 0; i < count; i++)
        result.push_back(insns[i].mnemonic);
    cs_free(insns, count);
    cs_close(&handle);
    return result;
}

// ── V2 hash variants at different prefix lengths ─────────────────────────────

uint64_t hashMnemPrefix(const std::vector<std::string>& mnems, int prefixLen) {
    FNV1a64 h;
    int count = 0;
    for (auto& m : mnems) {
        if (count >= prefixLen) break;
        h.updateByte(0);
        h.update(reinterpret_cast<const uint8_t*>(m.data()), static_cast<int>(m.size()));
        count++;
    }
    return h.digest();
}

uint64_t hashMnemNoCalls(const std::vector<std::string>& mnems) {
    FNV1a64 h;
    for (auto& m : mnems) {
        if (isCallOrJump(m)) continue;
        h.updateByte(0);
        h.update(reinterpret_cast<const uint8_t*>(m.data()), static_cast<int>(m.size()));
    }
    return h.digest();
}

uint64_t hashMnemFull(const std::vector<std::string>& mnems) {
    return hashMnemPrefix(mnems, static_cast<int>(mnems.size()));
}

// ── Program loading ─────────────────────────────────────────────────────────

std::unique_ptr<ProgramDB> loadBinary(const std::string& path, const std::string& name) {
    auto loader = createLoader();
    if (!loader || !loader->load(path)) {
        std::cerr << "Failed to load: " << path << "\n";
        return nullptr;
    }

    auto* ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);

    auto prog = std::make_unique<ProgramDB>(name, nullptr, nullptr);
    auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog->getAddressFactory());
    if (addrFactory) {
        addrFactory->addAddressSpace(ramSpace);
        addrFactory->addAddressSpace(constSpace);
        addrFactory->addAddressSpace(uniqueSpace);
        addrFactory->addAddressSpace(regSpace);
        addrFactory->addAddressSpace(stackSpace);
        addrFactory->setDefaultSpace(ramSpace);
    }

    if (!loader->populateProgram(prog.get())) {
        std::cerr << "populateProgram failed for: " << path << "\n";
        return nullptr;
    }

    {
        FunctionDiscoveryOptions fdOpts;
        fdOpts.includeExternalInFunctionManager = true;
        FunctionDiscoveryAnalyzer fdAnalyzer(fdOpts);
        fdAnalyzer.analyzeLoader(*loader);
        auto* fm = prog->getFunctionManager();
        auto* rs = const_cast<AddressSpace*>(addrFactory ? addrFactory->getDefaultAddressSpace() : nullptr);
        if (fm && rs) fdAnalyzer.applyTo(*fm, rs);
    }

    auto analysisMgr = std::make_unique<AutoAnalysisManager>(prog.get());
    analysisMgr->registerAnalyzer(std::make_unique<EntryPointAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DisassemblyAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartDataPostAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionStartFuncAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataSectionFunctionScannerAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ApplyDataArchiveAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FragmentMergeAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FidAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<FunctionBodyFinalizer>());
    analysisMgr->registerAnalyzer(std::make_unique<ExternalEntryFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataRefFunctionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<PEExceptionAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ImportThunkAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ScalarOperandAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<OperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<DataOperandReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<ConstantPropagationAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackReferenceAnalyzer>());
    analysisMgr->registerAnalyzer(std::make_unique<StackVariableAnalyzer>());
    analysisMgr->analyze(&ghidra::getDummyMonitor());

    return prog;
}

// ── Function extraction ─────────────────────────────────────────────────────

std::vector<FuncRecord> extractFunctions(Program* prog) {
    std::vector<FuncRecord> result;
    if (!prog) return result;

    FunctionManager* fm = prog->getFunctionManager();
    Memory* mem = prog->getMemory();
    if (!fm || !mem) return result;

    FunctionFingerprinter fingerprinter;
    FunctionIterator it = fm->getFunctions(true);
    while (it.hasNext()) {
        Function* f = it.next();
        if (!f) continue;

        std::string name = f->getName();
        if (!NamingService::isAutoGeneratedName(name)) {
            FuncRecord rec;
            rec.name = name;
            rec.address = f->getEntryPoint().getOffset();
            rec.bodySize = static_cast<int>(f->getBody().getNumAddresses());
            MemoryBlock* block = mem->getBlock(f->getEntryPoint());
            if (block) {
                rec.bytesCode = block->getBytes(f->getEntryPoint(), rec.rawBytes, 32);
            } else {
                rec.bytesCode = 0;
            }

            FunctionFingerprint fp = fingerprinter.compute(f, prog);
            rec.v1FullHash  = fp.v1.fullHash;
            rec.v1ShortHash = fp.v1.shortHash;

            auto mnems = disassembleMnemonics(mem, f->getEntryPoint(), 32);
            rec.instrCount = static_cast<int>(mnems.size());
            for (size_t i = 0; i < mnems.size(); i++) {
                if (i > 0) rec.mnemonicSequence += ",";
                rec.mnemonicSequence += mnems[i];
            }
            // Store raw mnemonics in rawBytes (reusing for V2 audit)
            // We'll compute V2 hashes on-the-fly from mnemonicSequence

            result.push_back(rec);
        }
    }
    return result;
}

// Helper: split comma-separated mnemonic string back to vector
std::vector<std::string> splitMnems(const std::string& seq) {
    std::vector<std::string> result;
    size_t start = 0;
    while (start < seq.size()) {
        size_t comma = seq.find(',', start);
        if (comma == std::string::npos) {
            result.push_back(seq.substr(start));
            break;
        }
        result.push_back(seq.substr(start, comma - start));
        start = comma + 1;
    }
    return result;
}

// ── Match measurement ───────────────────────────────────────────────────────

struct MatchResult {
    std::string label;
    int totalPairs;
    int exactMatches;
    int uniqueHashesA;
    int uniqueHashesB;
    int collisionsA;
    int collisionsB;
    int matchedOnlyByThis;  // matches unique to this strategy
};

MatchResult measureStrategy(
    const std::string& label,
    const std::vector<FuncRecord>& funcsA,
    const std::vector<FuncRecord>& funcsB,
    std::function<uint64_t(const FuncRecord&)> getHash,
    const std::unordered_set<std::string>* referenceMatches = nullptr)
{
    MatchResult mr;
    mr.label = label;
    mr.totalPairs = 0;
    mr.exactMatches = 0;
    mr.collisionsA = 0;
    mr.collisionsB = 0;
    mr.matchedOnlyByThis = 0;

    std::unordered_map<std::string, std::unordered_set<uint64_t>> nameHashesA, nameHashesB;
    std::unordered_set<uint64_t> allHashesA, allHashesB;

    for (auto& f : funcsA) {
        uint64_t h = getHash(f);
        if (h == 0) continue;
        nameHashesA[f.name].insert(h);
        allHashesA.insert(h);
    }
    for (auto& f : funcsB) {
        uint64_t h = getHash(f);
        if (h == 0) continue;
        nameHashesB[f.name].insert(h);
        allHashesB.insert(h);
    }

    mr.uniqueHashesA = static_cast<int>(allHashesA.size());
    mr.uniqueHashesB = static_cast<int>(allHashesB.size());

    {
        std::unordered_map<uint64_t, std::unordered_set<std::string>> hashMapA;
        for (auto& f : funcsA) {
            uint64_t h = getHash(f);
            if (h == 0) continue;
            hashMapA[h].insert(f.name);
        }
        for (auto& [h, names] : hashMapA)
            if (names.size() > 1) mr.collisionsA += static_cast<int>(names.size());
    }
    {
        std::unordered_map<uint64_t, std::unordered_set<std::string>> hashMapB;
        for (auto& f : funcsB) {
            uint64_t h = getHash(f);
            if (h == 0) continue;
            hashMapB[h].insert(f.name);
        }
        for (auto& [h, names] : hashMapB)
            if (names.size() > 1) mr.collisionsB += static_cast<int>(names.size());
    }

    std::unordered_set<std::string> thisMatches;
    for (auto& [name, hashesA] : nameHashesA) {
        auto itB = nameHashesB.find(name);
        if (itB == nameHashesB.end()) continue;
        auto& hashesB = itB->second;
        mr.totalPairs += static_cast<int>(hashesA.size() * hashesB.size());
        for (uint64_t ha : hashesA) {
            if (hashesB.count(ha)) {
                mr.exactMatches++;
                thisMatches.insert(name);
            }
        }
    }

    if (referenceMatches) {
        for (auto& n : thisMatches)
            if (!referenceMatches->count(n)) mr.matchedOnlyByThis++;
    }

    return mr;
}

// Body-size disambiguation: count matches where hash matches AND body sizes are within 20%
MatchResult measureWithBodySize(
    const std::string& label,
    const std::vector<FuncRecord>& funcsA,
    const std::vector<FuncRecord>& funcsB,
    std::function<uint64_t(const FuncRecord&)> getHash)
{
    MatchResult mr;
    mr.label = label;
    mr.totalPairs = 0;
    mr.exactMatches = 0;
    mr.collisionsA = 0;
    mr.collisionsB = 0;
    mr.matchedOnlyByThis = 0;

    // Build hash -> list of (name, bodySize) for both
    std::unordered_map<uint64_t, std::vector<std::pair<std::string, int>>> hashToFuncsA, hashToFuncsB;

    for (auto& f : funcsA) {
        uint64_t h = getHash(f);
        if (h == 0) continue;
        hashToFuncsA[h].push_back({f.name, f.bodySize});
    }
    for (auto& f : funcsB) {
        uint64_t h = getHash(f);
        if (h == 0) continue;
        hashToFuncsB[h].push_back({f.name, f.bodySize});
    }

    // Count unique hashes
    std::unordered_set<uint64_t> allHashesA, allHashesB;
    for (auto& [h, _] : hashToFuncsA) allHashesA.insert(h);
    for (auto& [h, _] : hashToFuncsB) allHashesB.insert(h);
    mr.uniqueHashesA = static_cast<int>(allHashesA.size());
    mr.uniqueHashesB = static_cast<int>(allHashesB.size());

    // Count collisions
    for (auto& [h, funcs] : hashToFuncsA)
        if (funcs.size() > 1) mr.collisionsA += static_cast<int>(funcs.size());
    for (auto& [h, funcs] : hashToFuncsB)
        if (funcs.size() > 1) mr.collisionsB += static_cast<int>(funcs.size());

    // Match: same hash + body sizes within 20%
    for (auto& [h, listA] : hashToFuncsA) {
        auto itB = hashToFuncsB.find(h);
        if (itB == hashToFuncsB.end()) continue;
        auto& listB = itB->second;

        for (auto& [nameA, sizeA] : listA) {
            for (auto& [nameB, sizeB] : listB) {
                if (nameA != nameB) continue;
                mr.totalPairs++;
                int minSize = std::min(sizeA, sizeB);
                int maxSize = std::max(sizeA, sizeB);
                if (minSize == 0 || maxSize <= minSize * 1.2) {
                    mr.exactMatches++;
                }
            }
        }
    }

    return mr;
}

} // anonymous namespace

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: enigma_fingerprint_audit <binary_a> <binary_b> [--csv output.csv]\n";
        return 1;
    }

    std::string pathA = argv[1];
    std::string pathB = argv[2];
    std::string csvPath;
    for (int i = 3; i < argc; ++i)
        if (std::string(argv[i]) == "--csv" && i + 1 < argc) csvPath = argv[i + 1];

    auto progA = loadBinary(pathA, "fpA");
    auto progB = loadBinary(pathB, "fpB");
    if (!progA || !progB) return 1;

    auto funcsA = extractFunctions(progA.get());
    auto funcsB = extractFunctions(progB.get());

    std::cerr << "Binary A: " << pathA << " — " << funcsA.size() << " named functions\n";
    std::cerr << "Binary B: " << pathB << " — " << funcsB.size() << " named functions\n";

    std::unordered_set<std::string> namesA, namesB;
    for (auto& f : funcsA) namesA.insert(f.name);
    for (auto& f : funcsB) namesB.insert(f.name);
    std::vector<std::string> sharedNames;
    for (auto& n : namesA)
        if (namesB.count(n)) sharedNames.push_back(n);

    std::cerr << "Shared named functions: " << sharedNames.size() << "\n\n";

    // Collect shared names for reference matching
    std::unordered_set<std::string> sharedSet(sharedNames.begin(), sharedNames.end());

    // ── V1 strategies ────────────────────────────────────────────────────────
    auto v1Results = measureStrategy("V1_fullHash", funcsA, funcsB,
        [](const FuncRecord& f){ return f.v1FullHash; });
    auto v1Short = measureStrategy("V1_shortHash", funcsA, funcsB,
        [](const FuncRecord& f){ return f.v1ShortHash; });

    // ── V2 prefix length sweep ───────────────────────────────────────────────
    auto v2Full = measureStrategy("V2_fullSeq", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemFull(m); });

    auto v2NoCalls = measureStrategy("V2_noCalls", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemNoCalls(m); });

    auto v2P8 = measureStrategy("V2_prefix8", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 8); });

    auto v2P12 = measureStrategy("V2_prefix12", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 12); });

    auto v2P16 = measureStrategy("V2_prefix16", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 16); });

    auto v2P20 = measureStrategy("V2_prefix20", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 20); });

    // ── V2 + body size disambiguation ────────────────────────────────────────
    auto v2P8body = measureWithBodySize("V2_p8+body", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 8); });

    auto v2P12body = measureWithBodySize("V2_p12+body", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 12); });

    auto v2P16body = measureWithBodySize("V2_p16+body", funcsA, funcsB,
        [](const FuncRecord& f){ auto m = splitMnems(f.mnemonicSequence); return hashMnemPrefix(m, 16); });

    // ── Report ───────────────────────────────────────────────────────────────
    std::vector<MatchResult*> allResults = {
        &v1Results, &v1Short,
        &v2Full, &v2NoCalls, &v2P8, &v2P12, &v2P16, &v2P20,
        &v2P8body, &v2P12body, &v2P16body
    };

    std::cerr << "=== Fingerprint V1 vs V2 — Prefix Length Sweep ===\n\n";
    std::cerr << std::left;
    std::cerr << std::setw(18) << "Strategy"
              << std::setw(11) << "Unique(A)"
              << std::setw(11) << "Unique(B)"
              << std::setw(9)  << "Pairs"
              << std::setw(11) << "Matches"
              << std::setw(12) << "Collide(A)"
              << std::setw(12) << "Collide(B)"
              << std::setw(10) << "Match%"
              << std::setw(10) << "Collide%" << "\n";
    std::cerr << std::string(104, '-') << "\n";

    for (auto* r : allResults) {
        double matchRate = (r->totalPairs > 0) ? (100.0 * r->exactMatches / r->totalPairs) : 0.0;
        int totalHashes = r->uniqueHashesA + r->uniqueHashesB;
        double collisionRate = (totalHashes > 0)
            ? (100.0 * (r->collisionsA + r->collisionsB) / totalHashes) : 0.0;

        std::cerr << std::setw(18) << r->label
                  << std::setw(11) << r->uniqueHashesA
                  << std::setw(11) << r->uniqueHashesB
                  << std::setw(9)  << r->totalPairs
                  << std::setw(11) << r->exactMatches
                  << std::setw(12) << r->collisionsA
                  << std::setw(12) << r->collisionsB
                  << std::setw(10) << std::fixed << std::setprecision(1) << matchRate
                  << std::setw(10) << collisionRate << "\n";
    }

    // Per-function match analysis for V2_prefix8 (best coverage)
    if (!sharedNames.empty()) {
        std::cerr << "\n=== Per-Function V2 Prefix8 Match Detail ===\n\n";
        std::cerr << std::left << std::setw(30) << "Name"
                  << std::setw(12) << "V1?"
                  << std::setw(12) << "V2_p8?"
                  << std::setw(12) << "V2_p12?"
                  << std::setw(12) << "V2_p16?"
                  << "Body(A/B)\n";
        std::cerr << std::string(90, '-') << "\n";

        for (auto& name : sharedNames) {
            const FuncRecord* recA = nullptr;
            for (auto& f : funcsA) { if (f.name == name) { recA = &f; break; } }
            const FuncRecord* recB = nullptr;
            for (auto& f : funcsB) { if (f.name == name) { recB = &f; break; } }
            if (!recA || !recB) continue;

            bool v1 = (recA->v1FullHash == recB->v1FullHash && recA->v1FullHash != 0);

            auto mnA = splitMnems(recA->mnemonicSequence);
            auto mnB = splitMnems(recB->mnemonicSequence);
            bool v2p8  = (hashMnemPrefix(mnA, 8)  == hashMnemPrefix(mnB, 8)  && hashMnemPrefix(mnA, 8) != 0);
            bool v2p12 = (hashMnemPrefix(mnA, 12) == hashMnemPrefix(mnB, 12) && hashMnemPrefix(mnA, 12) != 0);
            bool v2p16 = (hashMnemPrefix(mnA, 16) == hashMnemPrefix(mnB, 16) && hashMnemPrefix(mnA, 16) != 0);

            std::cerr << std::setw(30) << name
                      << std::setw(12) << (v1 ? "YES" : "no")
                      << std::setw(12) << (v2p8 ? "YES" : "no")
                      << std::setw(12) << (v2p12 ? "YES" : "no")
                      << std::setw(12) << (v2p16 ? "YES" : "no")
                      << recA->bodySize << "/" << recB->bodySize << "\n";
        }
    }

    if (!csvPath.empty()) {
        std::ofstream csv(csvPath);
        csv << "strategy,unique_a,unique_b,pairs,matches,collisions_a,collisions_b,match_rate,collision_rate\n";
        for (auto* r : allResults) {
            double matchRate = (r->totalPairs > 0) ? (100.0 * r->exactMatches / r->totalPairs) : 0.0;
            double collisionRate = ((r->uniqueHashesA + r->uniqueHashesB) > 0)
                ? (100.0 * (r->collisionsA + r->collisionsB) / (r->uniqueHashesA + r->uniqueHashesB)) : 0.0;
            csv << r->label << ","
                << r->uniqueHashesA << "," << r->uniqueHashesB << ","
                << r->totalPairs << "," << r->exactMatches << ","
                << r->collisionsA << "," << r->collisionsB << ","
                << std::fixed << std::setprecision(2) << matchRate << ","
                << collisionRate << "\n";
        }
        std::cerr << "\nCSV written to: " << csvPath << "\n";
    }

    return 0;
}
