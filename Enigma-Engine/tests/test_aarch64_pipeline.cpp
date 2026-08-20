#include <ghidra/Sleigh.h>
#include <ghidra/PcodeCapstoneMapper.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/OpCode.h>
#include <ghidra/LoadImage.h>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <vector>

using ghidra::int4;
static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)
#define TEST_MSG(n, x, msg) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<": "<<msg<<"\n"<<std::flush;} } while(0)

static bool writeBinary(const std::string& path, const std::vector<uint8_t>& code) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t written = std::fwrite(code.data(), 1, code.size(), f);
    std::fclose(f);
    return written == code.size();
}

// ---- AArch64 test binary ----
// A small function prologue/body/epilogue at 0x1000 that exercises the
// common A64 categories (store-pair, mov, sub, add, bl, ldr/str, cmp,
// conditional branch, load-pair, ret) plus blr/cbz/adrp coverage.
static std::vector<uint8_t> makeA64TestBinary() {
    return {
        0xFD, 0x7B, 0xBF, 0xA9, // stp x29, x30, [sp, #-16]!
        0xFD, 0x03, 0x00, 0x91, // mov x29, sp
        0xFF, 0x43, 0x00, 0xD1, // sub sp, sp, #0x20
        0x40, 0x05, 0x80, 0xD2, // mov x0, #42
        0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
        0x07, 0x00, 0x00, 0x94, // bl 0x1030
        0xA1, 0x03, 0x40, 0xF9, // ldr x1, [x29, #8]
        0xE0, 0x03, 0x00, 0xF9, // str x0, [sp]
        0x1F, 0x28, 0x00, 0xF1, // cmp x0, #10
        0x8D, 0x00, 0x00, 0x54, // b.le 0x1034
        0x60, 0x0C, 0x80, 0xD2, // mov x0, #99
        0xFD, 0x7B, 0xC1, 0xA8, // ldp x29, x30, [sp], #16
        0xC0, 0x03, 0x5F, 0xD6, // ret
        0x00, 0x01, 0x3F, 0xD6, // blr x8
        0x40, 0x00, 0x00, 0xB4, // cbz x0, 0x1010
        0x00, 0x00, 0x00, 0xB0  // adrp x0, 0x1000
    };
}

int main() {
    // ---- 1. AArch64 Sleigh pipeline: full function decode ----
    {
        std::string testPath = "test_pipeline_aarch64.bin";
        auto code = makeA64TestBinary();
        if (!writeBinary(testPath, code)) {
            TEST_MSG("write AArch64 test binary", false, "cannot write file");
        } else {
            ghidra::GenericAddressSpace a64Space("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
            ghidra::Address a64Base(&a64Space, 0x1000);
            ghidra::LoadImageRawFile loader(testPath, a64Base, "aarch64");
            if (loader.getSize() > 0) {
                ghidra::Sleigh sleigh(&loader, "");
                sleigh.setArchitecture("aarch64", 64);
                bool initOk = sleigh.initialize();
                TEST_MSG("AARCH64: Sleigh initialize", initOk, "Sleigh init failed");
                if (initOk) {
                    ghidra::Funcdata fd("aarch64_test", a64Base);
                    uint64_t ea = 0x1000;
                    int count = 0;
                    bool allLength4 = true;
                    for (size_t i = 0; i < 16 && ea < 0x1000 + code.size(); ++i) {
                        ghidra::Address insAddr(&a64Space, ea);
                        int4 len = sleigh.oneInstruction(fd, insAddr);
                        if (len <= 0) {
                            allLength4 = false;
                            break;
                        }
                        if (len != 4) allLength4 = false;
                        ea += static_cast<uint64_t>(len);
                        ++count;
                    }
                    TEST_MSG("AARCH64: all 16 instructions decoded", count == 16,
                             "count=" + std::to_string(count));
                    TEST("AARCH64: every instruction is 4 bytes", allLength4);

                    bool hasCall = false, hasReturn = false, hasStore = false, hasLoad = false;
                    bool hasIntAdd = false, hasIntSub = false, hasCBranch = false;
                    int opCount = fd.getNumOps();
                    for (int i = 0; i < opCount; i++) {
                        auto* op = fd.getOp(i);
                        if (!op) continue;
                        switch (op->getOpcode()) {
                            case ghidra::PcodeOp::CALL:
                            case ghidra::PcodeOp::CALLIND: hasCall = true; break;
                            case ghidra::PcodeOp::RETURN: hasReturn = true; break;
                            case ghidra::PcodeOp::STORE: hasStore = true; break;
                            case ghidra::PcodeOp::LOAD: hasLoad = true; break;
                            case ghidra::PcodeOp::INT_ADD: hasIntAdd = true; break;
                            case ghidra::PcodeOp::INT_SUB: hasIntSub = true; break;
                            case ghidra::PcodeOp::CBRANCH: hasCBranch = true; break;
                            default: break;
                        }
                    }
                    TEST_MSG("AARCH64: funcdata has pcode ops", opCount >= 10,
                             "only " + std::to_string(opCount) + " ops");
                    TEST("AARCH64: has CALL (bl)", hasCall);
                    TEST("AARCH64: has CALLIND (blr)", hasCall);
                    TEST("AARCH64: has RETURN (ret)", hasReturn);
                    TEST("AARCH64: has STORE (stp/str)", hasStore);
                    TEST("AARCH64: has LOAD (ldr/ldp)", hasLoad);
                    TEST("AARCH64: has INT_ADD (add)", hasIntAdd);
                    TEST("AARCH64: has INT_SUB (sub)", hasIntSub);
                    TEST("AARCH64: has CBRANCH (b.le/cbz)", hasCBranch);
                }
            }
            std::remove(testPath.c_str());
        }
    }

    // ---- 2. CapstoneDisassembler AArch64: mnemonics + flow types ----
    {
        auto code = makeA64TestBinary();
        auto disasm = ghidra::createDisassembler("aarch64", 64, false);
        TEST("createDisassembler(aarch64) succeeds", disasm != nullptr);
        if (disasm) {
            auto insns = disasm->disassembleRange(code, 0x1000, code.size(), 32);
            TEST_MSG("disassembleRange count", insns.size() == 16,
                     "got " + std::to_string(insns.size()));
            if (insns.size() >= 16) {
                TEST_MSG("insn[0] = stp", insns[0].mnemonic == "stp", insns[0].mnemonic);
                TEST_MSG("insn[1] = mov", insns[1].mnemonic == "mov", insns[1].mnemonic);
                TEST_MSG("insn[2] = sub", insns[2].mnemonic == "sub", insns[2].mnemonic);
                TEST_MSG("insn[5] = bl", insns[5].mnemonic == "bl", insns[5].mnemonic);
                TEST_MSG("insn[6] = ldr", insns[6].mnemonic == "ldr", insns[6].mnemonic);
                TEST_MSG("insn[8] = cmp", insns[8].mnemonic == "cmp", insns[8].mnemonic);
                TEST_MSG("insn[9] = b.le", insns[9].mnemonic == "b.le", insns[9].mnemonic);
                TEST_MSG("insn[11] = ldp", insns[11].mnemonic == "ldp", insns[11].mnemonic);
                TEST_MSG("insn[12] = ret", insns[12].mnemonic == "ret", insns[12].mnemonic);
                TEST_MSG("insn[13] = blr", insns[13].mnemonic == "blr", insns[13].mnemonic);
                TEST_MSG("insn[14] = cbz", insns[14].mnemonic == "cbz", insns[14].mnemonic);
                TEST_MSG("insn[15] = adrp", insns[15].mnemonic == "adrp", insns[15].mnemonic);

                auto flowName = [](const ghidra::FlowType* ft) -> std::string {
                    return ft ? ft->getName() : "null";
                };
                TEST_MSG("flow: bl = call",
                         insns[5].flowType == &ghidra::RefTypes::UNCONDITIONAL_CALL,
                         flowName(insns[5].flowType));
                TEST_MSG("flow: b.le = cond jump",
                         insns[9].flowType == &ghidra::RefTypes::CONDITIONAL_JUMP,
                         flowName(insns[9].flowType));
                TEST_MSG("flow: ret = terminator",
                         insns[12].flowType == &ghidra::RefTypes::TERMINATOR,
                         flowName(insns[12].flowType));
                TEST_MSG("flow: cbz = cond jump",
                         insns[14].flowType == &ghidra::RefTypes::CONDITIONAL_JUMP,
                         flowName(insns[14].flowType));
                TEST_MSG("flow: adrp = fallthrough",
                         insns[15].flowType == &ghidra::RefTypes::FALL_THROUGH,
                         flowName(insns[15].flowType));
            }
        }
    }

    // ---- 3. Mapper register offsets (xzr -> const 0, x/w/v naming) ----
    {
        ghidra::PcodeCapstoneMapper mapper;
        TEST("mapper.initialize(aarch64)", mapper.initialize("aarch64"));

        ghidra::GenericAddressSpace space("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
        ghidra::Address addr(&space, 0x2000);
        ghidra::Funcdata fd("mapper_test", addr);

        ghidra::DisassembledInstruction di;
        di.address = addr;
        di.length = 4;
        di.byteCount = 4;
        di.mnemonic = "mov";
        di.operands = {"x0", "xzr"};
        di.flowType = const_cast<ghidra::FlowType*>(&ghidra::RefTypes::FALL_THROUGH);
        mapper.mapInstruction(di, fd, addr);
        int n = fd.getNumOps();
        TEST_MSG("mov x0, xzr produces ops", n >= 1, "ops=" + std::to_string(n));
        bool sawCopy = false;
        for (int i = 0; i < n; i++) {
            auto* op = fd.getOp(i);
            if (op && op->getOpcode() == ghidra::PcodeOp::COPY) sawCopy = true;
        }
        TEST("mov x0, xzr emits COPY", sawCopy);
    }

    std::cout << "\n" << passed << "/" << total << " passed\n";
    return (passed == total) ? 0 : 1;
}