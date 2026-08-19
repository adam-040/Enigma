/* ###
 * IP: Enigma Engine (original work)
 *
 * End-to-end test for GzfProgramImporter: imports a real Ghidra-produced
 * program database (.gbf) and asserts the resulting ProgramDB matches the
 * corpus ground truth (table record counts verified by enigma_gzf_inspect).
 *
 * Corpora are located via ENIGMA_CORPUS_DIR or by probing ../ and ../../
 * relative to the test's working directory; the test SKIPs (exit 0) when no
 * corpus is present so the suite stays green on machines without the data.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/BookmarkManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/ModuleManager.h>
#include <ghidra/ProgramContextImpl.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Relocation.h>
#include <ghidra/RelocationTableImpl.h>
#include <ghidra/TreeManager.h>
#include <ghidra/Variable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/import/GbfReader.h>
#include <ghidra/import/GzfProgramImporter.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace ghidra;

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

bool importAndCheck(const std::string& gbfPath, const std::string& programName, int expectedInst,
                    int expectedProtos, int expectedBlocks, int expectedSubs,
                    int expectedFileBytes, int expectedFunctions, int expectedThunks,
                    int expectedComments, int expectedRefs, int expectedRefsEntry,
                    int expectedExternalRefs,
                    int expectedContextRecords = -1, int expectedRegisterValueRanges = -1,
                    int expectedCategories = -1, int expectedBuiltins = -1,
                    int expectedComposites = -1, int expectedComponents = -1,
                    int expectedEnums = -1, int expectedEnumValues = -1,
                    int expectedFunctionDefs = -1, int expectedFunctionParams = -1,
                    int expectedPointers = -1, int expectedTypedefs = -1,
                    int expectedArrays = -1, int expectedDataUnits = -1,
                    int expectedDataTermStrings = -1, int expectedDataUnwind = -1,
                    int expectedDataRich = -1, int expectedDataPlaceholderLengths = -1,
                    int expectedFunctionReturnTypes = -1,
                    int expectedBookmarkTypes = -1, int expectedBookmarks = -1,
                    int expectedRelocations = -1, int expectedTrees = -1,
                    int expectedModules = -1, int expectedFragments = -1,
                    int expectedModuleRelationships = -1, int expectedFragmentRanges = -1,
                    int expectedScopeRanges = -1, int expectedFunctionsWithScopes = -1,
                    int expectedMetadata = -1,
                    int expectedRepeatableComments = -1, int expectedEntryPoints = -1,
                    int expectedCallFixups = -1, int expectedContextDefaults = -1,
                    int expectedSourceFiles = -1, int expectedSourceMapEntries = -1,
                    int expectedVariableStorages = -1, int expectedParameters = -1,
                    int expectedLocalVariables = -1) {
    std::ifstream in(gbfPath, std::ios::binary);
    if (!in) return false;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
    auto reader = GbfReader::fromMemory(std::move(bytes));
    GzfProgramImporter importer(*reader);
    std::unique_ptr<ProgramDB> program = importer.import(programName);
    const GzfProgramImporter::Stats& st = importer.getStats();
    {
        const auto& warns = importer.getWarnings();
        for (size_t i = 0; i < warns.size() && i < 3; ++i) {
            std::cout << "  warn: " << warns[i] << "\n";
        }
    }

    TEST(programName + " stats.instructions", st.instructions == expectedInst);
    TEST(programName + " stats.prototypes", st.prototypes == expectedProtos);
    TEST(programName + " stats.memoryBlocks", st.memoryBlocks == expectedBlocks);
    TEST(programName + " stats.subMemoryBlocks", st.subMemoryBlocks == expectedSubs);
    TEST(programName + " stats.fileBytes", st.fileBytes == expectedFileBytes);
    TEST(programName + " stats.functions", st.functions == expectedFunctions);
    TEST(programName + " stats.thunks", st.thunks == expectedThunks);
    TEST(programName + " stats.commentsApplied", st.commentsApplied == expectedComments);
    TEST(programName + " stats.references", st.references == expectedRefs);
    TEST(programName + " stats.refsEntryPoint", st.refsEntryPoint == expectedRefsEntry);
    TEST(programName + " stats.externalReferences",
         st.externalReferences == expectedExternalRefs);
    TEST(programName + " stats.refsExternTarget", st.refsExternTarget == 0);
    TEST(programName + " stats.refsBadRecords", st.refsBadRecords == 0);
    TEST(programName + " no disassembly failures", st.disassemblyFailures == 0);

    // P3g: no silent data loss is the invariant on every corpus.
    TEST(programName + " no unresolved datatype refs", st.datatypeUnresolvedRefs == 0);
    TEST(programName + " no component offset mismatches", st.componentOffsetMismatches == 0);
    TEST(programName + " no data conflicts", st.dataConflicts == 0);
    TEST(programName + " no unresolved data types", st.dataUnresolvedType == 0);
    TEST(programName + " no unresolved data lengths", st.dataUnresolvedLength == 0);

    if (expectedContextRecords >= 0) {
        TEST(programName + " stats.contextRecords",
             st.contextRecords == expectedContextRecords);
        TEST(programName + " stats.contextRecordsBad", st.contextRecordsBad == 0);
    }
    if (expectedRegisterValueRanges >= 0) {
        TEST(programName + " stats.registerValueRanges",
             st.registerValueRanges == expectedRegisterValueRanges);
        TEST(programName + " stats.registerValueBad", st.registerValueBad == 0);
    }

    if (expectedCategories >= 0) {
        TEST(programName + " stats.categories", st.categories == expectedCategories);
        TEST(programName + " stats.builtins (incl. aliased/placeholders)",
             st.builtins + st.builtinPlaceholders + st.builtinAliased == expectedBuiltins);
        TEST(programName + " stats.composites", st.composites == expectedComposites);
        TEST(programName + " stats.components", st.components == expectedComponents);
        TEST(programName + " stats.enums", st.enums == expectedEnums);
        TEST(programName + " stats.enumValues", st.enumValues == expectedEnumValues);
        TEST(programName + " stats.functionDefs", st.functionDefs == expectedFunctionDefs);
        TEST(programName + " stats.functionParams", st.functionParams == expectedFunctionParams);
        TEST(programName + " stats.pointers", st.pointers == expectedPointers);
        TEST(programName + " stats.typedefs", st.typedefs == expectedTypedefs);
        TEST(programName + " stats.arrays", st.arrays == expectedArrays);
        TEST(programName + " stats.dataUnits", st.dataUnits == expectedDataUnits);
        TEST(programName + " stats.dataTerminatedStrings",
             st.dataTerminatedStrings == expectedDataTermStrings);
        TEST(programName + " stats.dataUnwindInfo", st.dataUnwindInfo == expectedDataUnwind);
        TEST(programName + " stats.dataRichHeader", st.dataRichHeader == expectedDataRich);
        TEST(programName + " stats.dataPlaceholderLengths",
             st.dataPlaceholderLengths == expectedDataPlaceholderLengths);
        TEST(programName + " stats.functionReturnTypes",
             st.functionReturnTypes == expectedFunctionReturnTypes);
    }

    if (expectedBookmarkTypes >= 0) {
        TEST(programName + " stats.bookmarkTypes", st.bookmarkTypes == expectedBookmarkTypes);
        TEST(programName + " stats.bookmarks", st.bookmarks == expectedBookmarks);
        TEST(programName + " stats.bookmarksBad", st.bookmarksBad == 0);
    }
    if (expectedRelocations >= 0) {
        TEST(programName + " stats.relocations", st.relocations == expectedRelocations);
        TEST(programName + " stats.relocationsBad", st.relocationsBad == 0);
    }
    if (expectedTrees >= 0) {
        TEST(programName + " stats.trees", st.trees == expectedTrees);
        TEST(programName + " stats.modules", st.modules == expectedModules);
        TEST(programName + " stats.fragments", st.fragments == expectedFragments);
        TEST(programName + " stats.moduleRelationships",
             st.moduleRelationships == expectedModuleRelationships);
        TEST(programName + " stats.fragmentRanges", st.fragmentRanges == expectedFragmentRanges);
        TEST(programName + " stats.moduleTreeBad", st.moduleTreeBad == 0);
    }
    if (expectedScopeRanges >= 0) {
        TEST(programName + " stats.scopeRanges", st.scopeRanges == expectedScopeRanges);
        TEST(programName + " stats.functionsWithScopes",
             st.functionsWithScopes == expectedFunctionsWithScopes);
        TEST(programName + " stats.scopeBad", st.scopeBad == 0);
    }
    if (expectedMetadata >= 0) {
        TEST(programName + " stats.metadataRecords", st.metadataRecords == expectedMetadata);
    }
    std::cout << "  [" << programName << "] repComments=" << st.repeatableComments
              << " entryPoints=" << st.entryPoints
              << " callFixups=" << st.callFixups
              << " ctxDefaults=" << st.contextDefaults
              << " srcFiles=" << st.sourceFiles
              << " srcMap=" << st.sourceMapEntries
              << " srcMapBad=" << st.sourceMapBad
              << " storages=" << st.variableStorages
              << " params=" << st.parameters
              << " locals=" << st.localVariables
<< " varsBad=" << st.variablesBad << "\n";
    if (expectedRepeatableComments >= 0) {
        TEST(programName + " stats.repeatableComments",
             st.repeatableComments == expectedRepeatableComments);
    }
    if (expectedEntryPoints >= 0) {
        TEST(programName + " stats.entryPoints", st.entryPoints == expectedEntryPoints);
    }
    if (expectedCallFixups >= 0) {
        TEST(programName + " stats.callFixups", st.callFixups == expectedCallFixups);
    }
    if (expectedContextDefaults >= 0) {
        TEST(programName + " stats.contextDefaults",
             st.contextDefaults == expectedContextDefaults);
    }
    if (expectedSourceFiles >= 0) {
        TEST(programName + " stats.sourceFiles", st.sourceFiles == expectedSourceFiles);
        TEST(programName + " stats.sourceMapEntries",
             st.sourceMapEntries == expectedSourceMapEntries);
        TEST(programName + " stats.sourceMapBad", st.sourceMapBad == 0);
    }
    if (expectedVariableStorages >= 0) {
        TEST(programName + " stats.variableStorages",
             st.variableStorages == expectedVariableStorages);
        TEST(programName + " stats.parameters", st.parameters == expectedParameters);
        TEST(programName + " stats.localVariables",
             st.localVariables == expectedLocalVariables);
        TEST(programName + " stats.variablesBad", st.variablesBad == 0);
    }

    TEST(programName + " listing count", program->getListing()->getInstructionCount() ==
                                             static_cast<size_t>(expectedInst));
    TEST(programName + " function count",
         program->getFunctionManager()->getFunctionCount() == expectedFunctions);
    TEST(programName + " reference manager count",
         program->getReferenceManager()->getReferenceCount() == expectedRefs);
    TEST(programName + " external locations restored",
         program->getExternalManager()->getExternalLocationCount() > 0);
    return true;
}

}  // namespace

int main() {
    // notepad_test.exe database
    std::string notepadGbf =
        findCorpus("ghidra_proj.rep/idata/00/~00000001.db/db.1.gbf");
    if (!notepadGbf.empty()) {
        TEST("found notepad corpus", true);
        importAndCheck(notepadGbf, "notepad_test.exe", /*instructions=*/35367,
                       /*prototypes=*/894, /*blocks=*/9, /*subs=*/10, /*fileBytes=*/1,
                       /*functions=*/794, /*thunks=*/41, /*comments=*/1004,
                       /*refs=*/19449, /*refsEntry=*/1, /*externalRefs=*/1735,
                       /*contextRecords=*/894, /*registerValueRanges=*/35,
                       /*categories=*/41, /*builtins=*/32, /*composites=*/162,
                       /*components=*/873, /*enums=*/7, /*enumValues=*/94,
                       /*functionDefs=*/96, /*functionParams=*/253,
                       /*pointers=*/242, /*typedefs=*/198, /*arrays=*/49,
                       /*dataUnits=*/2960,
                       /*dataTermStrings=*/0, /*dataUnwind=*/0, /*dataRich=*/0,
                       /*dataPlaceholderLengths=*/0,
                       /*functionReturnTypes=*/426,
                       /*bookmarkTypes=*/2, /*bookmarks=*/75,
                       /*relocations=*/348, /*trees=*/1, /*modules=*/1,
                       /*fragments=*/10, /*moduleRelationships=*/10,
                       /*fragmentRanges=*/11, /*scopeRanges=*/551,
                       /*functionsWithScopes=*/498, /*metadata=*/43);

        // Ground-truth bytes: the whole PE is one file-bytes source, so the
        // first block ("Headers" at image offset 0) starts with the MZ header;
        // its first sub-block is type FILE_BYTES (chain head 10, 200,704 bytes
        // -> exact MZ PE).
        std::ifstream in(notepadGbf, std::ios::binary);
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
        auto reader = GbfReader::fromMemory(std::move(bytes));
        GzfProgramImporter importer(*reader);
        std::unique_ptr<ProgramDB> program = importer.import("notepad_test.exe");
        TEST("notepad calling conventions restored",
             program->getFunctionManager()->getCallingConventionNames().size() >= 4);
        // Register value maps: GS_OFFSET current values over the executable
        // ranges (DatabaseRangeMapAdapter "Range Map - Register_GS_OFFSET").
        // Value blob = [mask 8B MSB-first][value 8B MSB-first]; corpus mask
        // is full, value is the TEB address 0x000000FF00000000.
        auto* ctx = dynamic_cast<ProgramContextImpl*>(program->getProgramContext());
        TEST("notepad program context is ProgramContextImpl", ctx != nullptr);
        if (ctx) {
            const auto& rvs = ctx->getRegisterValues();
            TEST("notepad GS_OFFSET ranges restored", rvs.size() == 35);
            for (const auto& kv : rvs) {
                TEST("notepad GS_OFFSET register name",
                     kv.first.reg->getName() == "GS_OFFSET");
                const auto& mask = kv.second->getMask();
                const bool fullMask =
                    mask.size() == 8 &&
                    std::all_of(mask.begin(), mask.end(),
                                [](uint8_t b) { return b == 0xFF; });
                TEST("notepad GS_OFFSET full mask", fullMask);
                TEST("notepad GS_OFFSET value",
                     kv.second->getUnsignedOffset() == 0x000000FF00000000ull);
            }
        }
        // P3g ground truth: the PE header data units (IMAGE_RICH_HEADER at
        // 0x80 and the 32-bit image-base offset pointer at 0x4), expressed as
        // full VAs (notepad corpus image offset is 0x140000000).
        AddressSpace* space =
            const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
        TEST("notepad image base restored",
             program->getImageBase() == Address(space, 0x140000000));
        TEST("notepad effective image base restored",
             program->getEffectiveImageBase() == Address(space, 0x140000000));
        Data* rich = program->getListing()->getDataAt(Address(space, 0x140000080));
        TEST("notepad rich header data unit at 0x140000080",
             rich != nullptr && rich->getLength() >= 16);
        // The corpus places the ImageBaseOffset32 unit at image offset
        // 0x27384; IBO32 is a 32-bit pointer-typedef (length 4).
        Data* ibo32 = program->getListing()->getDataAt(Address(space, 0x140027384));
        TEST("notepad image-base offset data unit at 0x140027384",
             ibo32 != nullptr && ibo32->getLength() == 4);
        TEST("notepad data type manager has types",
             program->getDataTypeManager()->getDataTypeCount(true) > 700);
        Memory* mem = program->getMemory();
        MemoryBlock* text = mem->getBlock(".text");
        TEST("notepad .text block exists", text != nullptr);
        if (text) {
            TEST("notepad .text executable", text->isExecute());
            MemoryBlock* headers = mem->getBlock("Headers");
            TEST("notepad Headers block exists", headers != nullptr);
            if (headers) {
                TEST("notepad Headers block starts with MZ",
                     mem->getByte(headers->getStart()) == 'M' &&
                         mem->getByte(headers->getStart().add(1)) == 'Z');
            }
        }
        // P3i: module tree restored from the Trees/Module/Fragment/
        // Relationship/Range Map tables.
        TreeManager* tm = program->getTreeManager();
        TEST("notepad tree manager present", tm != nullptr);
        if (tm) {
            const std::vector<std::string> names = tm->getTreeNames();
            TEST("notepad tree name restored",
                 names.size() == 1 && names[0] == "Program Tree");
            ProgramModule* root = tm->getRootModule("Program Tree");
            TEST("notepad root module renamed", root != nullptr &&
                                                    root->getName() == "notepad_test.exe");
            bool childrenOk = false;
            for (const auto& pair : tm->getModules()) {
                if (pair.first == "Program Tree") {
                    childrenOk = pair.second->getChildrenIDs(0).size() == 10;
                    break;
                }
            }
            TEST("notepad root children restored", childrenOk);
            ProgramFragment* headersFrag =
                tm->getFragment("Program Tree", Address(space, 0x140000000));
            TEST("notepad Headers fragment covers 0x140000000-0x1400003FF",
                 headersFrag != nullptr && headersFrag->getName() == "Headers" &&
                     headersFrag->contains(Address(space, 0x140000000)) &&
                     headersFrag->contains(Address(space, 0x1400003FF)) &&
                     !headersFrag->contains(Address(space, 0x140000400)));
            ProgramFragment* tdbFrag = tm->getFragment(
                "Program Tree", Address(space, static_cast<int64_t>(0xFDC0000000ull)));
            TEST("notepad tdb fragment covers 0xFDC0000000-0xFDC000184F",
                 tdbFrag != nullptr && tdbFrag->getName() == "tdb" &&
                     tdbFrag->contains(
                         Address(space, static_cast<int64_t>(0xFDC0000000ull))) &&
                     tdbFrag->contains(
                         Address(space, static_cast<int64_t>(0xFDC000184Full))));
        }
        // P3i: bookmarks (BookmarkDBAdapterV3 per-type tables).
        Bookmark* peBookmark =
            program->getBookmarkManager()->getBookmark(Address(space, 0x14002D0C8), "PE Header");
        TEST("notepad PE header bookmark restored", peBookmark != nullptr);
        if (peBookmark) {
            TEST("notepad PE header bookmark comment",
                 peBookmark->getComment().find("IMAGE_DIRECTORY_ENTRY") !=
                     std::string::npos);
            TEST("notepad bookmark count",
                 program->getBookmarkManager()->getBookmarkCount() == 75);
        }
        // P3i: relocations (RelocationDBAdapterV6 records).
        auto* relocTable = dynamic_cast<RelocationTableImpl*>(program->getRelocationTable());
        TEST("notepad relocation table is RelocationTableImpl", relocTable != nullptr);
        if (relocTable) {
            TEST("notepad relocation count", relocTable->getRelocationCount() == 348);
            // The corpus has two relocation records at 0x26000 (keys 0 and
            // 221): the first is type 10, the second type 0; both SKIPPED.
            std::vector<Relocation> relocs =
                relocTable->getRelocations(Address(space, 0x140026000));
            TEST("notepad relocation at 0x140026000", relocs.size() == 2);
            if (relocs.size() == 2) {
                TEST("notepad relocation status SKIPPED",
                     relocs[0].getStatus() == Relocation::Status::SKIPPED);
                TEST("notepad relocation type 10", relocs[0].getType() == 10);
                TEST("notepad relocation values null", relocs[0].getValues().empty());
                TEST("notepad relocation type 0 duplicate",
                     relocs[1].getStatus() == Relocation::Status::SKIPPED &&
                         relocs[1].getType() == 0);
            }
        }
        // P3i: metadata (ProgramMetadataManager key/value store).
        const auto& md = program->getMetadata();
        TEST("notepad metadata program name",
             md.count("Program Name") == 1 && md.at("Program Name") == "notepad_test.exe");
        TEST("notepad metadata language id",
             md.count("Language ID") == 1 && md.at("Language ID") == "x86:LE:64:default (4.6)");
        TEST("notepad metadata compiler id",
             md.count("Compiler ID") == 1 && md.at("Compiler ID") == "windows");
        // P3i: function bodies restored from "Range Map - SCOPE ADDRESSES"
        // (first corpus range: function 6 covering 0x1008..0x108C).
        Function* f6 = program->getFunctionManager()->getFunctionContaining(Address(space, 0x140001008));
        TEST("notepad function scope restored at 0x140001008",
             f6 != nullptr && f6->getBody().contains(Address(space, 0x140001008)) &&
                 f6->getBody().contains(Address(space, 0x14000108C)));
    } else {
        std::cout << "[SKIP] notepad corpus not found\n";
    }

    // key.exe database
    std::string keyGbf =
        findCorpus("ghidra_proj_key.rep/idata/00/~00000000.db/db.1.gbf");
    if (!keyGbf.empty()) {
        TEST("found key.exe corpus", true);
        importAndCheck(keyGbf, "key.exe", /*instructions=*/15051, /*prototypes=*/778,
                       /*blocks=*/20, /*subs=*/20, /*fileBytes=*/1, /*functions=*/231,
                       /*thunks=*/56, /*comments=*/518,
                       /*refs=*/6708, /*refsEntry=*/137, /*externalRefs=*/144,
                       /*contextRecords=*/778, /*registerValueRanges=*/0,
                       /*categories=*/-1, /*builtins=*/-1, /*composites=*/-1,
                       /*components=*/-1, /*enums=*/-1, /*enumValues=*/-1,
                       /*functionDefs=*/-1, /*functionParams=*/-1,
                       /*pointers=*/-1, /*typedefs=*/-1, /*arrays=*/-1,
                       /*dataUnits=*/-1, /*dataTermStrings=*/-1,
                       /*dataUnwind=*/-1, /*dataRich=*/-1,
                       /*dataPlaceholderLengths=*/-1, /*functionReturnTypes=*/-1,
                       /*bookmarkTypes=*/3, /*bookmarks=*/12,
                       /*relocations=*/64, /*trees=*/2, /*modules=*/57,
                       /*fragments=*/237, /*moduleRelationships=*/292,
                       /*fragmentRanges=*/388, /*scopeRanges=*/561,
                       /*functionsWithScopes=*/176, /*metadata=*/31);
    } else {
        std::cout << "[SKIP] key.exe corpus not found\n";
    }

    // pro.exe database
    std::string proGbf =
        findCorpus("ghidra_proj_pro.rep/idata/00/~00000000.db/db.1.gbf");
    if (!proGbf.empty()) {
        TEST("found pro.exe corpus", true);
        importAndCheck(proGbf, "pro.exe", /*instructions=*/1410, /*prototypes=*/227,
                       /*blocks=*/20, /*subs=*/20, /*fileBytes=*/1, /*functions=*/109,
                       /*thunks=*/32, /*comments=*/231,
                       /*refs=*/987, /*refsEntry=*/74, /*externalRefs=*/81,
                       /*contextRecords=*/227, /*registerValueRanges=*/0,
                       /*categories=*/-1, /*builtins=*/-1, /*composites=*/-1,
                       /*components=*/-1, /*enums=*/-1, /*enumValues=*/-1,
                       /*functionDefs=*/-1, /*functionParams=*/-1,
                       /*pointers=*/-1, /*typedefs=*/-1, /*arrays=*/-1,
                       /*dataUnits=*/-1, /*dataTermStrings=*/-1,
                       /*dataUnwind=*/-1, /*dataRich=*/-1,
                       /*dataPlaceholderLengths=*/-1, /*functionReturnTypes=*/-1,
                       /*bookmarkTypes=*/3, /*bookmarks=*/9,
                       /*relocations=*/46, /*trees=*/2, /*modules=*/35,
                       /*fragments=*/137, /*moduleRelationships=*/170,
                       /*fragmentRanges=*/199, /*scopeRanges=*/130,
                       /*functionsWithScopes=*/78, /*metadata=*/31);
    } else {
        std::cout << "[SKIP] pro.exe corpus not found\n";
    }

    // pass.exe database (Ghidra 12.1.3: bracket-form "Variable Storage"
    // records, e.g. Stack[-0x4c]:4, linked via the variable-space symbol
    // address, plus Pointers Length signed-byte regression).  Counts are
    // the 12.1.3 analysis baseline (12.0.4 differed: composites 95,
    // components 655, arrays 62, dataUnits 3792).
    std::string passGbf =
        findCorpus("pass_proj.rep/idata/00/~00000000.db/db.16.gbf");
    if (!passGbf.empty()) {
        TEST("found pass.exe corpus", true);
        importAndCheck(passGbf, "pass.exe", /*instructions=*/15406, /*prototypes=*/764,
                       /*blocks=*/20, /*subs=*/20, /*fileBytes=*/1, /*functions=*/241,
                       /*thunks=*/60, /*comments=*/584,
                       /*refs=*/6954, /*refsEntry=*/140, /*externalRefs=*/157,
                       /*contextRecords=*/764, /*registerValueRanges=*/0,
                       /*categories=*/84, /*builtins=*/31, /*composites=*/96,
                       /*components=*/657, /*enums=*/9, /*enumValues=*/130,
                       /*functionDefs=*/140, /*functionParams=*/272,
                       /*pointers=*/110, /*typedefs=*/148, /*arrays=*/61,
                       /*dataUnits=*/3910,
                       /*dataTermStrings=*/0, /*dataUnwind=*/0, /*dataRich=*/0,
                       /*dataPlaceholderLengths=*/0,
                       /*functionReturnTypes=*/175,
                       /*bookmarkTypes=*/3, /*bookmarks=*/13,
                       /*relocations=*/64, /*trees=*/2, /*modules=*/59,
                       /*fragments=*/242, /*moduleRelationships=*/299,
                       /*fragmentRanges=*/399, /*scopeRanges=*/567,
                       /*functionsWithScopes=*/182, /*metadata=*/31,
                       /*repeatableComments=*/-1, /*entryPoints=*/-1,
                       /*callFixups=*/-1, /*contextDefaults=*/-1,
                       /*sourceFiles=*/97, /*sourceMapEntries=*/11975,
                       /*variableStorages=*/111, /*parameters=*/335,
                       /*localVariables=*/231);

        // ---- Variable Storage regression: Ghidra 12 bracket-form stack
        // records ("Stack[-0x4c]:4") linked through the variable-space
        // symbol address; every valid record must decode to the exact
        // offset/size, never BAD/unknown.
        {
            std::ifstream in(passGbf, std::ios::binary);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                       std::istreambuf_iterator<char>());
            auto reader = GbfReader::fromMemory(std::move(bytes));
            GzfProgramImporter importer(*reader);
            std::unique_ptr<ProgramDB> program = importer.import("pass.exe");
            auto findFn = [&](const std::string& n) -> Function* {
                for (FunctionIterator it =
                         program->getFunctionManager()->getFunctions(true);
                     it.hasNext();) {
                    Function* f = it.next();
                    if (f && f->getName() == n) return f;
                }
                return nullptr;
            };
            auto findLocal = [](Function* f, const std::string& n) -> const Variable* {
                if (!f) return nullptr;
                for (const Variable* v : f->getLocalVariables()) {
                    if (v->getName() == n) return v;
                }
                return nullptr;
            };
            Function* mainFn = findFn("main");
            TEST("pass main function found", mainFn != nullptr);
            if (mainFn) {
                const auto& ml = mainFn->getLocalVariables();
                TEST("pass main 3 locals", ml.size() == 3);
                if (ml.size() == 3) {
                    // Records Stack[-0x52]:8 / Stack[-0x4a]:2 / Stack[-0x48]:1
                    // (keys 64/32/57) in exact Ghidra form.
                    TEST("pass main locals exact stack storage",
                         ml[0]->hasStackStorage() &&
                             ml[0]->getStackOffset() == -82 &&
                             ml[0]->getDataType()->getLength() == 8 &&
                             ml[1]->hasStackStorage() &&
                             ml[1]->getStackOffset() == -74 &&
                             ml[1]->getDataType()->getLength() == 2 &&
                             ml[2]->hasStackStorage() &&
                             ml[2]->getStackOffset() == -72 &&
                             ml[2]->getDataType()->getLength() == 1);
                }
                // main's params carry the <UNASSIGNED> record (key 2):
                // unassigned is Ghidra's truth, not a decode failure.
                TEST("pass main params unassigned",
                     mainFn->getParameters().size() == 3 &&
                         !mainFn->getParameters()[0]->hasAssignedStorage());
            }
            Function* scanfFn = findFn("__mingw_scanf");
            TEST("pass __mingw_scanf found", scanfFn != nullptr);
            if (scanfFn) {
                const Variable* argp = findLocal(scanfFn, "argp");
                TEST("pass __mingw_scanf argp stack -32 size 8",
                     argp != nullptr && argp->hasStackStorage() &&
                         argp->getStackOffset() == -32 &&
                         argp->getDataType()->getLength() == 8);
            }
            Function* printfFn = findFn("__mingw_printf");
            TEST("pass __mingw_printf found", printfFn != nullptr);
            if (printfFn) {
                const Variable* argv = findLocal(printfFn, "argv");
                TEST("pass __mingw_printf argv stack -32 size 8",
                     argv != nullptr && argv->hasStackStorage() &&
                         argv->getStackOffset() == -32 &&
                         argv->getDataType()->getLength() == 8);
            }
            Function* tmainFn = findFn("__tmainCRTStartup");
            TEST("pass __tmainCRTStartup found", tmainFn != nullptr);
            if (tmainFn) {
                const Variable* startinfo = findLocal(tmainFn, "startinfo");
                // Record Stack[-0x4c]:4 (key 1); the corpus declares
                // _startupinfo as 4 bytes.
                TEST("pass startinfo stack -76 size 4",
                     startinfo != nullptr && startinfo->hasStackStorage() &&
                         startinfo->getStackOffset() == -76 &&
                         startinfo->getDataType()->getLength() == 4 &&
                         startinfo->getDataType()->getName() == "_startupinfo");
            }
            Function* relocFn = findFn("_pei386_runtime_relocator");
            TEST("pass _pei386_runtime_relocator found", relocFn != nullptr);
            if (relocFn) {
                const Variable* reldata = findLocal(relocFn, "reldata");
                // Record Stack[-0x40]:8 (key 3).
                TEST("pass reldata stack -64 size 8",
                     reldata != nullptr && reldata->hasStackStorage() &&
                         reldata->getStackOffset() == -64 &&
                         reldata->getDataType()->getLength() == 8);
            }
            // No variable anywhere may end up with BAD storage (the old
            // importer dropped every stack record to unassigned/unknown).
            size_t badCount = 0, unassignedParams = 0, totalVars = 0;
            for (FunctionIterator it =
                     program->getFunctionManager()->getFunctions(true);
                 it.hasNext();) {
                Function* f = it.next();
                if (!f) continue;
                for (const Variable* p : f->getParameters()) {
                    totalVars++;
                    // Unassigned (<UNASSIGNED> record) is Ghidra-truthful and
                    // has no varnodes (isValid()==false); only the explicit
                    // BAD marker counts as a decode failure.
                    if (p->getVariableStorage().isBadStorage()) {
                        badCount++;
                        std::cout << "  [pass.exe] BAD param " << f->getName() << "::"
                                  << p->getName() << "\n";
                    }
                    if (!p->hasAssignedStorage()) unassignedParams++;
                }
                for (const Variable* l : f->getLocalVariables()) {
                    totalVars++;
                    if (l->getVariableStorage().isBadStorage()) {
                        badCount++;
                        std::cout << "  [pass.exe] BAD local " << f->getName() << "::"
                                  << l->getName() << "\n";
                    }
                }
            }
            TEST("pass no BAD storage on any variable", badCount == 0);

            // ---- Positive-stack storage: x64 shadow-space home slots
            // (records Stack[0x8..0x20]) must decode as positive stack
            // offsets, never dropped or sign-flipped.
            auto findLocalByStorage = [](Function* f, int offset, int size) -> const Variable* {
                if (!f) return nullptr;
                for (const Variable* v : f->getLocalVariables()) {
                    if (v->hasStackStorage() && v->getStackOffset() == offset &&
                        v->getDataType()->getLength() == size) {
                        return v;
                    }
                }
                return nullptr;
            };
            Function* printfFn2 = findFn("__mingw_printf");
            TEST("pass __mingw_printf shadow space locals",
                 printfFn2 != nullptr &&
                     findLocalByStorage(printfFn2, 0x10, 8) != nullptr &&
                     findLocalByStorage(printfFn2, 0x18, 8) != nullptr &&
                     findLocalByStorage(printfFn2, 0x20, 8) != nullptr);
            Function* scanfFn2 = findFn("__mingw_scanf");
            TEST("pass __mingw_scanf shadow space locals",
                 scanfFn2 != nullptr &&
                     findLocalByStorage(scanfFn2, 0x10, 8) != nullptr &&
                     findLocalByStorage(scanfFn2, 0x18, 8) != nullptr &&
                     findLocalByStorage(scanfFn2, 0x20, 8) != nullptr);
            Function* inChFn = findFn("in_ch");
            TEST("pass in_ch shadow space locals",
                 inChFn != nullptr && findLocalByStorage(inChFn, 0x8, 8) != nullptr &&
                     findLocalByStorage(inChFn, 0x10, 8) != nullptr);
            Function* wcrtombFn = findFn("__mingw_wcrtomb_cp");
            TEST("pass __mingw_wcrtomb_cp shadow space locals",
                 wcrtombFn != nullptr && findLocalByStorage(wcrtombFn, 0x8, 8) != nullptr &&
                     findLocalByStorage(wcrtombFn, 0x10, 2) != nullptr);
        }

        // ---- Pointers regression: Length is a signed byte; -1 (default
        // pointer size) must survive as the engine default, and no
        // length-255 "char *2040" corruption may exist.
        {
            std::ifstream in(passGbf, std::ios::binary);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                       std::istreambuf_iterator<char>());
            auto reader = GbfReader::fromMemory(std::move(bytes));
            GzfProgramImporter importer(*reader);
            std::unique_ptr<ProgramDB> program = importer.import("pass.exe");
            DataTypeManager* dtm = program->getDataTypeManager();
            size_t ptr255 = 0, ptrDefault = 0, badNames = 0;
            for (DataType* dt : dtm->getDataTypes()) {
                if (!dt) continue;
                if (auto* p = dynamic_cast<PointerDataType*>(dt)) {
                    if (p->getLength() == 255) ptr255++;
                    if (p->getLength() == 8) ptrDefault++;
                    if (p->getName().find("*2040") != std::string::npos) badNames++;
                }
            }
            TEST("pass no pointer datatype with length 255", ptr255 == 0);
            TEST("pass no '*2040' pointer names", badNames == 0);
            TEST("pass default pointers decode to 8 bytes", ptrDefault > 0);
        }
    } else {
        std::cout << "[SKIP] pass.exe corpus not found\n";
    }

    std::cout << "\n=== Gzf Program Importer Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";
    return (passed == total) ? 0 : 1;
}
