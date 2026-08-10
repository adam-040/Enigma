// enigma_patch_cli.cpp — load a binary, apply byte patches, export patched binary.
// Usage: enigma_patch_cli.exe <input.bin> <addr:hex> <orig_hex> <new_hex> <output.bin>
#include <ghidra/BinaryLoader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/patch/PatchManager.h>
#include <ghidra/patch/BytePatch.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <cstdint>

static std::vector<uint8_t> parseHex(const std::string& s) {
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        auto hx = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hx(s[i]), lo = hx(s[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc < 6) {
        std::cerr << "Usage: enigma_patch_cli <input> <addr:hex> <orig_hex> <new_hex> <output>\n";
        return 2;
    }
    std::string inPath = argv[1];
    uint64_t addr = strtoull(argv[2], nullptr, 16);
    std::vector<uint8_t> origBytes = parseHex(argv[3]);
    std::vector<uint8_t> newBytes = parseHex(argv[4]);
    std::string outPath = argv[5];
    if (origBytes.empty() || newBytes.empty()) {
        std::cerr << "bad hex\n";
        return 2;
    }

    auto loader = ghidra::createLoader();
    if (!loader || !loader->load(inPath)) {
        std::cerr << "load failed\n";
        return 1;
    }
    std::cout << "Loaded " << inPath << " format=" << loader->getFormatName()
              << " arch=" << loader->getArchitecture()
              << " bits=" << loader->getBitness() << "\n" << std::flush;

    std::unique_ptr<ghidra::ProgramDB> prog(new ghidra::ProgramDB("patched", nullptr, nullptr));
    auto* af = dynamic_cast<ghidra::ProgramAddressFactory*>(prog->getAddressFactory());
    if (!af) { std::cerr << "no address factory\n"; return 1; }
    auto* ram = new ghidra::GenericAddressSpace("ram", 64, ghidra::AddressSpace::TYPE_RAM, 1);
    af->addAddressSpace(ram);
    af->setDefaultSpace(ram);
    af->setConstantSpace(ram);
    af->setUniqueSpace(ram);
    af->setRegisterSpace(ram);
    af->setStackSpace(ram);
    std::cout << "ProgramDB + spaces OK\n" << std::flush;
    if (!loader->populateProgram(prog.get())) {
        std::cerr << "populateProgram failed\n";
        return 1;
    }
    std::cout << "populateProgram OK\n" << std::flush;

    ghidra::patch::PatchManager pm;
    pm.setProgram(prog.get());
    pm.setBinaryLoader(loader.get());
    pm.installPatchMemory(prog.get());
    std::cout << "PatchManager OK\n" << std::flush;

    auto patch = std::make_unique<ghidra::patch::BytePatch>(
        addr, origBytes, newBytes, "cli_patch", "CLI patch");
    pm.addPatch(std::move(patch));
    pm.applyAllActive();
    std::cout << "Patch applied\n" << std::flush;

    std::cout << "Patch at 0x" << std::hex << addr << ": "
              << argv[3] << " -> " << argv[4] << std::dec << "\n";
    std::cout << "Active patches: " << pm.activePatchCount() << "\n" << std::flush;

    if (!pm.exportPatchedBinary(outPath)) {
        std::cerr << "export FAILED\n";
        return 1;
    }
    std::cout << "Export OK\n" << std::flush;

    // Verify: read output, check bytes at the file offset
    uint64_t fileOff = loader->virtualAddressToFileOffset(addr);
    std::ifstream fin(outPath, std::ios::binary);
    std::vector<uint8_t> buf(fileOff + newBytes.size());
    fin.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    bool ok = true;
    for (size_t i = 0; i < newBytes.size(); ++i) {
        if (buf[fileOff + i] != newBytes[i]) { ok = false; break; }
    }
    std::cout << "File offset: 0x" << std::hex << fileOff << std::dec << "\n";
    std::cout << (ok ? "VERIFY OK: patched bytes present in output\n"
                     : "VERIFY FAIL: patched bytes NOT in output\n");
    pm.releasePatchMemory();
    prog.reset();
    loader.reset();
    return ok ? 0 : 1;
}
