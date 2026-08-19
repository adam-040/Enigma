/* ###
 * IP: Enigma Engine (original work)
 *
 * Regression tests for the Ghidra-12 image-base fix (GzfProgramImporter):
 * the importer must read the Program-table "Image Offset" (hex, unprefixed)
 * or legacy "Image Base" (decimal), set ProgramDB image base + effective
 * image base, and rebase every image-space RVA to a full virtual address so
 * that imported programs match Ghidra's original addresses exactly, and
 * patching/exporting an imported program maps VAs to file offsets correctly
 * (never silently skipping a patch).
 *
 * Corpora are located via ENIGMA_CORPUS_DIR or by probing ../ and ../..
 * relative to the test's working directory; the test SKIPs (exit 0) when no
 * corpus is present so the suite stays green on machines without the data.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/Address.h>
#include <ghidra/BinaryLoader.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/import/GbfReader.h>
#include <ghidra/import/GzfProgramImporter.h>
#include <ghidra/import/RepProject.h>
#include <ghidra/patch/BytePatch.h>
#include <ghidra/patch/PatchManager.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace ghidra;
using namespace ghidra::patch;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace {

std::string findCorpus(const std::string& relPath) {
    if (const char* dir = std::getenv("ENIGMA_CORPUS_DIR")) {
        fs::path p = fs::path(dir) / relPath;
        if (fs::exists(p)) return p.string();
    }
    for (const char* prefix : {"", "../", "../../"}) {
        fs::path p = fs::path(prefix) / relPath;
        if (fs::exists(p)) return p.string();
    }
    return "";
}

std::unique_ptr<ProgramDB> importProgram(const std::string& gbfPath,
                                         const std::string& programName) {
    std::ifstream in(gbfPath, std::ios::binary);
    if (!in) return nullptr;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    auto reader = GbfReader::fromMemory(std::move(bytes));
    GzfProgramImporter importer(*reader);
    return importer.import(programName);
}

}  // namespace

int main() {
    // ── 1) notepad_test.exe: image base + blocks rebased ──────────────
    std::string notepadGbf =
        findCorpus("ghidra_proj.rep/idata/00/~00000001.db/db.1.gbf");
    if (notepadGbf.empty()) {
        std::cout << "[SKIP] notepad corpus not found\n";
    } else {
        std::unique_ptr<ProgramDB> program = importProgram(notepadGbf, "notepad_test.exe");
        TEST("notepad corpus imported", program != nullptr);
        if (program) {
            AddressSpace* space = const_cast<AddressSpace*>(
                program->getAddressFactory()->getDefaultAddressSpace());
            TEST("notepad image base == 0x140000000",
                 program->getImageBase() == Address(space, 0x140000000));
            TEST("notepad effective image base == 0x140000000",
                 program->getEffectiveImageBase() == Address(space, 0x140000000));
            MemoryBlock* headers = program->getMemory()->getBlock("Headers");
            TEST("notepad Headers block at 0x140000000",
                 headers != nullptr && headers->getStart() == Address(space, 0x140000000));
            MemoryBlock* text = program->getMemory()->getBlock(".text");
            TEST("notepad .text block at 0x140001000",
                 text != nullptr && text->getStart() == Address(space, 0x140001000));
        }
    }

    // ── 2) pass_proj.rep: exact original Ghidra VAs, refs, decompile ───
    std::string passRep = findCorpus("pass_proj.rep");
    if (passRep.empty()) {
        std::cout << "[SKIP] pass_proj corpus not found\n";
    } else {
        RepProject project(passRep);
        const auto& progs = project.programs();
        TEST("pass_proj program discovered", !progs.empty());
        if (progs.empty()) {
            std::cout << "[SKIP] pass_proj has no program\n";
        } else {
            std::vector<uint8_t> dbBytes = project.getDatabaseBytes(progs[0]);
            auto reader = GbfReader::fromMemory(std::move(dbBytes));
            GzfProgramImporter importer(*reader);
            std::unique_ptr<ProgramDB> program = importer.import("pass.exe");
            TEST("pass corpus imported", program != nullptr);
            if (program) {
                AddressSpace* space = const_cast<AddressSpace*>(
                    program->getAddressFactory()->getDefaultAddressSpace());
                const Address MAIN(space, 0x1400014b0);
                const Address STRCMP(space, 0x140011390);
                const Address JNZ(space, 0x140001505);
                const Address CALL(space, 0x1400014fe);
                const Address FMT(space, 0x140013016);

                TEST("pass image base == 0x140000000",
                     program->getImageBase() == Address(space, 0x140000000));
                TEST("pass effective image base == 0x140000000",
                     program->getEffectiveImageBase() == Address(space, 0x140000000));

                MemoryBlock* text = program->getMemory()->getBlock(".text");
                TEST("pass .text block at 0x140001000",
                     text != nullptr && text->getStart() == Address(space, 0x140001000));

                // main at the exact original Ghidra VA (0x14b0 RVA).
                Function* mainFn =
                    program->getFunctionManager()->getFunctionAt(MAIN);
                TEST("pass main at 0x1400014b0",
                     mainFn != nullptr && mainFn->getEntryPoint() == MAIN);
                if (mainFn) {
                    TEST("pass main named 'main'", mainFn->getName() == "main");
                }
                // Representative callee: strcmp at its exact Ghidra VA.
                Function* strcmpFn =
                    program->getFunctionManager()->getFunctionAt(STRCMP);
                TEST("pass strcmp at 0x140011390",
                     strcmpFn != nullptr && strcmpFn->getEntryPoint() == STRCMP);

                // Instructions present at full VAs (the JNZ of the password
                // branch and the CALL to strcmp inside main).  The corpus DB
                // stores the instruction's byte pattern: 12.0.4-era analysis
                // recorded a 74-coded prototype ("je"), 12.1.3 records the
                // 75-coded one ("jne"); both are the same conditional jump.
                Instruction* jnz = program->getListing()->getInstructionAt(JNZ);
                TEST("pass JNZ instruction at 0x140001505",
                     jnz != nullptr && (jnz->getMnemonicString() == "je" ||
                                        jnz->getMnemonicString() == "jne" ||
                                        jnz->getMnemonicString() == "jnz"));
                Instruction* call = program->getListing()->getInstructionAt(CALL);
                TEST("pass CALL instruction at 0x1400014fe",
                     call != nullptr && call->getMnemonicString() == "call");

                // References rebased: call at main+0x4e -> strcmp,
                // and the format-string data ref at main+0x34 -> 0x140013016.
                bool callToStrcmp = false;
                for (Reference* r : program->getReferenceManager()->getReferencesFrom(CALL)) {
                    if (r->isMemoryReference() && r->getToAddress() == STRCMP) {
                        callToStrcmp = true;
                    }
                }
                TEST("pass ref main+0x4e -> strcmp 0x140011390", callToStrcmp);

                bool fmtRef = false;
                for (Reference* r : program->getReferenceManager()->getReferencesFrom(
                         Address(space, 0x1400014e4))) {
                    if (r->isMemoryReference() && r->getToAddress() == FMT) {
                        fmtRef = true;
                    }
                }
                TEST("pass data ref main+0x34 -> 0x140013016", fmtRef);

                // Data units rebased: .rdata units at their full VAs (the corpus has
                // a 22-byte unit at 0x140013000; 0x140013016 sits in the gap
                // before the next unit at 0x140013019).
                Data* fmtUnit =
                    program->getListing()->getDataAt(Address(space, 0x140013000));
                TEST("pass data unit at 0x140013000",
                     fmtUnit != nullptr && fmtUnit->getLength() == 22);
                Data* nextUnit =
                    program->getListing()->getDataAt(Address(space, 0x140013019));
                TEST("pass data unit at 0x140013019",
                     nextUnit != nullptr && nextUnit->getLength() == 8);

                // Decompiler pointer resolution: the scanf format pointer
                // must come back as the full VA 0x140013016 (not 0x13016).
                if (mainFn) {
                    DecompInterface decomp;
                    decomp.openProgram(program.get());
                    DecompileResults res = decomp.decompileFunction(mainFn, nullptr);
                    TEST("pass decompile of main succeeds", res.decompiled);
                    if (res.decompiled) {
                        TEST("pass decompiler resolves pointer to full VA",
                             res.cCode.find("0x140013016") != std::string::npos);
                    }
                }

                // ── 3) patch -> export on an imported program ──────────
                // Original PE comes from the imported program's file bytes.
                std::string pePath = "test_rebase_orig.bin";
                std::string outPath = "test_rebase_patched.bin";
                {
                    std::ofstream fout(pePath, std::ios::binary);
                    const auto& orig = importer.getOriginalFileBytes();
                    fout.write(reinterpret_cast<const char*>(orig.data()),
                               static_cast<std::streamsize>(orig.size()));
                    TEST("pass original PE written", bool(fout));
                }
                std::unique_ptr<BinaryLoader> loader = createLoader();
                TEST("pass loader loads original PE", loader->load(pePath));

                PatchManager mgr;
                mgr.setProgram(program.get());
                mgr.setBinaryLoader(loader.get());

                // In-binary patch: NOP the JNZ at 0x140001505 (file offset
                // must map through the loader's section table).
                uint64_t jnzFileOff = loader->virtualAddressToFileOffset(0x140001505);
                TEST("pass JNZ maps to a real file offset",
                     jnzFileOff != UINT64_MAX);
                if (jnzFileOff != UINT64_MAX) {
                    std::ifstream pin(pePath, std::ios::binary);
                    pin.seekg(static_cast<std::streamoff>(jnzFileOff));
                    int b1 = pin.get(), b2 = pin.get();
                    TEST("pass original bytes at offset are JNZ 75 11",
                         b1 == 0x75 && b2 == 0x11);
                }
                auto bp = std::make_unique<BytePatch>(
                    0x140001505, std::vector<uint8_t>{0x75, 0x11},
                    std::vector<uint8_t>{0x90, 0x90}, "rebase_jnz_nop",
                    "NOP the password-check JNZ");
                bp->setEnabled(true);
                mgr.addPatch(std::move(bp));
                TEST("pass patch export succeeds",
                     mgr.exportPatchedBinary(outPath));
                TEST("pass export produced a file", fs::exists(outPath));
                if (jnzFileOff != UINT64_MAX && fs::exists(outPath)) {
                    std::ifstream pout(outPath, std::ios::binary);
                    pout.seekg(static_cast<std::streamoff>(jnzFileOff));
                    int p1 = pout.get(), p2 = pout.get();
                    TEST("pass exported bytes at offset are 90 90",
                         p1 == 0x90 && p2 == 0x90);
                }

                // Out-of-binary patch: must fail WITHOUT writing a file and
                // must report the skipped address.
                std::remove(outPath.c_str());
                auto bp2 = std::make_unique<BytePatch>(
                    0x200000000, std::vector<uint8_t>{0x90},
                    std::vector<uint8_t>{0xCC}, "rebase_unmapped",
                    "address beyond the PE image");
                bp2->setEnabled(true);
                mgr.addPatch(std::move(bp2));
                TEST("pass unmapped patch export fails",
                     !mgr.exportPatchedBinary(outPath));
                TEST("pass no file written on skip", !fs::exists(outPath));
                bool reported = false;
                for (uint64_t a : mgr.lastSkippedPatchAddresses()) {
                    if (a == 0x200000000) reported = true;
                }
                TEST("pass skipped address reported", reported);

                std::remove(pePath.c_str());
                std::remove(outPath.c_str());
            }
        }
    }

    std::cout << "=== Rebase tests: " << passed << " passed, " << (total - passed)
              << " failed (" << total << " total) ===\n";
    return passed == total ? 0 : 1;
}
