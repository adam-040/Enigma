// Phase 1: Repository + WorkingSnapshot + serialization round-trip

#include <ghidra/storage/Repository.h>
#include <ghidra/storage/SnapshotWriter.h>
#include <ghidra/storage/SnapshotReader.h>
#include <ghidra/storage/WorkingSnapshot.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include "program_generated.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cassert>
#include <string>
#include <ctime>
#include <vector>
#include <algorithm>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;} \
  else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

namespace fs = std::filesystem;
using namespace ghidra;
using namespace ghidra::storage;
namespace fb = fbschema;

static std::string uniqueTempDir() {
    auto ts = std::to_string(std::time(nullptr));
    std::string base = std::getenv("TEMP") ? std::getenv("TEMP") : ".";
    return base + "/enigma_stg_" + ts + "_" + std::to_string(rand() % 100000);
}

int main() {
    // === test 1: Repository::create + repository path functions ===
    {
        std::string repoPath = uniqueTempDir();
        bool ok = Repository::create(repoPath, "TestProj", "test.bin", "sha256abc",
                                     "x86:LE:64:default", "gcc", 0x100000);
        TEST("Repository::create returns true", ok);
        TEST("metadata dir exists", fs::exists(Repository::getMetadataDir(repoPath)));
        TEST("working dir exists", fs::exists(Repository::getWorkingDir(repoPath)));
        TEST("commits dir exists", fs::exists(Repository::getCommitsDir(repoPath)));
        TEST("index dir exists", fs::exists(Repository::getIndexDir(repoPath)));
        TEST("binary dir exists", fs::exists(Repository::getBinaryDir(repoPath)));
        TEST("project.meta exists", fs::exists(Repository::getProjectMetaPath(repoPath)));

        // Verify project.meta is valid FlatBuffers
        bool opened = Repository::open(repoPath);
        TEST("Repository::open succeeds", opened);

        // Test path functions
        TEST("metadata dir", Repository::getMetadataDir("/r") == "/r/metadata");
        TEST("working dir", Repository::getWorkingDir("/r") == "/r/working");
        TEST("commits dir", Repository::getCommitsDir("/r") == "/r/commits");
        TEST("index dir", Repository::getIndexDir("/r") == "/r/index/lmdb");
        TEST("binary dir", Repository::getBinaryDir("/r") == "/r/binary");
        TEST("project meta path", Repository::getProjectMetaPath("/r") == "/r/metadata/project.meta");
        TEST("branches meta path", Repository::getBranchesMetaPath("/r") == "/r/metadata/branches.meta");
        TEST("working snapshot path", Repository::getWorkingSnapshotPath("/r") == "/r/working/working.fbs");
        TEST("commit dir", Repository::getCommitDir("/r", "abc") == "/r/commits/abc");
        TEST("commit snapshot", Repository::getCommitSnapshotPath("/r", "abc") == "/r/commits/abc/snapshot.fbs");
        TEST("commit changeset", Repository::getCommitChangeSetPath("/r", "abc") == "/r/commits/abc/changeset.fbs");
        TEST("commit meta", Repository::getCommitMetaPath("/r", "abc") == "/r/commits/abc/commit.meta");

        // Cleanup
        fs::remove_all(repoPath);
    }

    // === test 2: SnapshotWriter::serialize empty ProgramDB ===
    {
        ProgramDB program;
        program.setName("empty");
        program.setLanguageID(LanguageID("x86:LE:64:default"));
        program.setCompilerSpecID(CompilerSpecID("gcc"));
        program.setImageBase(Address(nullptr, 0x100000));
        program.setMinAddress(Address(nullptr, 0x100000));
        program.setMaxAddress(Address(nullptr, 0x200000));

        auto data = SnapshotWriter::serialize(program);
        TEST("empty serialize returns non-empty buffer", data.size() > 0);

        // Deserialize back
        auto restored = SnapshotReader::deserialize(data.data(), data.size());
        TEST("deserialize returns non-null", restored != nullptr);
        TEST("name preserved", restored->getName() == "empty");
        TEST("languageID preserved", restored->getLanguageID().toString() == "x86:LE:64:default");
        TEST("compilerSpecID preserved", restored->getCompilerSpecID().toString() == "gcc");
        TEST("imageBase preserved", restored->getImageBase().getOffset() == 0x100000);
    }

    // === test 3: SnapshotWriter with a memory block ===
    {
        ProgramDB program;
        program.setName("test_mem");
        program.setLanguageID(LanguageID("x86:LE:64:default"));
        program.setCompilerSpecID(CompilerSpecID("gcc"));
        program.setImageBase(Address(nullptr, 0x100000));
        program.setMinAddress(Address(nullptr, 0x100000));
        program.setMaxAddress(Address(nullptr, 0x101000));

        auto mem = std::make_unique<DefaultMemory>(false);
        Address start(nullptr, 0x100000);
        mem->createInitializedBlock(".text", start, 0x1000, false);
        program.setMemory(mem.release());

        auto data = SnapshotWriter::serialize(program);
        TEST("block serialize returns non-empty buffer", data.size() > 0);

        auto restored = SnapshotReader::deserialize(data.data(), data.size());
        TEST("restored name", restored->getName() == "test_mem");
        TEST("restored imageBase", restored->getImageBase().getOffset() == 0x100000);

        Memory* restoredMem = restored->getMemory();
        TEST("restored memory exists", restoredMem != nullptr);
        auto blocks = restoredMem->getBlocks();
        TEST("restored has 1 block", blocks.size() == 1);
        if (blocks.size() >= 1) {
        TEST("block name", blocks[0]->getName() == ".text");
        TEST("block start", blocks[0]->getStart().getOffset() == 0x100000);
        TEST("block size", blocks[0]->getSize() == 0x1000);
        }
    }

    // === test 4: SnapshotReader::validateSchemaVersion ===
    {
        ProgramDB program;
        program.setName("version_test");
        auto data = SnapshotWriter::serialize(program);
        // Should not throw
        try {
            SnapshotReader::validateSchemaVersion(data.data(), data.size());
            TEST("validateSchemaVersion passes for version 1", true);
        } catch (...) {
            TEST("validateSchemaVersion passes for version 1", false);
        }

        // Corrupt data should fail
        std::vector<uint8_t> badData = {0, 0, 0, 0, 0, 0, 0, 0};
        bool threw = false;
        try {
            SnapshotReader::validateSchemaVersion(badData.data(), badData.size());
        } catch (...) {
            threw = true;
        }
        TEST("validateSchemaVersion throws on corrupt data", threw);
    }

    // === test 5: WorkingSnapshot atomic save + load ===
    {
        std::string tmpDir = uniqueTempDir();
        fs::create_directories(tmpDir);
        std::string snapPath = tmpDir + "/working.fbs";

        ProgramDB program;
        program.setName("atomic_test");
        program.setLanguageID(LanguageID("arm:LE:32:default"));
        program.setImageBase(Address(nullptr, 0x10000));
        program.setMinAddress(Address(nullptr, 0x10000));
        program.setMaxAddress(Address(nullptr, 0x11000));

        auto mem = std::make_unique<DefaultMemory>(false);
        Address initStart(nullptr, 0x10000);
        mem->createInitializedBlock(".init", initStart, 0x100, false);
        uint8_t initBytes[] = {0x55, 0x48, 0x89, 0xe5, 0xc3};
        mem->setBytes(initStart, initBytes, static_cast<int>(sizeof(initBytes)));
        program.setMemory(mem.release());

        bool saved = WorkingSnapshot::save(program, snapPath);
        TEST("WorkingSnapshot::save returns true", saved);
        TEST("snapshot file exists", fs::exists(snapPath));
        TEST("no .tmp file left", !fs::exists(snapPath + ".tmp"));

        auto loaded = WorkingSnapshot::load(snapPath);
        TEST("WorkingSnapshot::load returns non-null", loaded != nullptr);
        TEST("loaded name matches", loaded->getName() == "atomic_test");
        TEST("loaded languageID", loaded->getLanguageID().toString() == "arm:LE:32:default");

        Memory* loadedMem = loaded->getMemory();
        TEST("loaded memory exists", loadedMem != nullptr);
        auto loadedBlocks = loadedMem->getBlocks();
        TEST("loaded has 1 block", loadedBlocks.size() == 1);
        if (loadedBlocks.size() >= 1) {
            TEST("loaded block name", loadedBlocks[0]->getName() == ".init");
            uint8_t restoredBytes[sizeof(initBytes)] = {};
            int nread = loadedMem->getBytes(initStart, restoredBytes,
                                            static_cast<int>(sizeof(restoredBytes)));
            TEST("loaded memory bytes read", nread == static_cast<int>(sizeof(initBytes)));
            TEST("loaded memory bytes preserved",
                 std::equal(std::begin(initBytes), std::end(initBytes),
                            std::begin(restoredBytes)));
        }

        fs::remove_all(tmpDir);
    }

    // === test 6: round-trip with scalar metadata (bigEndian flag) ===
    {
        ProgramDB program;
        program.setName("endian_test");
        program.setLanguageID(LanguageID("ppc:BE:32:default"));
        program.setCompilerSpecID(CompilerSpecID("default"));
        program.setImageBase(Address(nullptr, 0x1000));

        auto mem = std::make_unique<DefaultMemory>(true);
        Address start(nullptr, 0x1000);
        mem->createInitializedBlock("data", start, 0x200, false);
        program.setMemory(mem.release());

        auto data = SnapshotWriter::serialize(program);
        auto snapshot = flatbuffers::GetRoot<fb::ProgramSnapshot>(data.data());
        TEST("schema_version is 1", snapshot->schema_version() == 1);
        TEST("big endian flag set in serialized data", snapshot->is_big_endian() == true);

        auto restored = SnapshotReader::deserialize(data.data(), data.size());
        TEST("restored endian test name", restored->getName() == "endian_test");
        TEST("restored imageBase", restored->getImageBase().getOffset() == 0x1000);
    }

    // === summary ===
    std::cout << "\n=== Phase 1 Storage Test Summary ===\n";
    std::cout << "Passed: " << passed << " / " << total << "\n";

    return (passed == total) ? 0 : 1;
}
