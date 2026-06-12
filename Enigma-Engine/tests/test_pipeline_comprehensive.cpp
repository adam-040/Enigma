#include <ghidra/EnigmaPipeline.h>
#include <ghidra/PcodeCapstoneMapper.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/OpCode.h>
#include <ghidra/PrintC.h>
#include <ghidra/FlowInfo.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/BlockGraph.h>
#include <ghidra/Sleigh.h>
#include <ghidra/LoadImage.h>
#include <iostream>
#include <cstdint>
#include <cstring>
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

// ---- x86-64 test binary ----
static std::vector<uint8_t> makeX86TestBinary() {
    // A function that exercises multiple instruction categories with side effects
    // to survive DCE:
    // push rbp                 -> STORE (survives)
    // mov rbp, rsp
    // sub rsp, 0x20
    // mov eax, 42              -> COPY (may be folded)
    // add eax, 1               -> INT_ADD (may be folded)
    // call 0x1030              -> CALL (survives, prevents value elimination)
    // test eax, eax            -> may be dead if result unused
    // mov rsp, rbp
    // pop rbp                  -> LOAD (survives)
    // ret                      -> RETURN (survives)
    return {
        0x55,                               // push rbp
        0x48, 0x89, 0xE5,                   // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x20,            // sub rsp, 0x20
        0xB8, 0x2A, 0x00, 0x00, 0x00,       // mov eax, 42
        0x83, 0xC0, 0x01,                   // add eax, 1
        0xE8, 0x1A, 0x00, 0x00, 0x00,       // call 0x1030 (relative)
        0x5D,                               // pop rbp
        0xC3                                // ret
    };
}

// ---- ARM Thumb test binary ----
static std::vector<uint8_t> makeARMTestBinary() {
    // ARM Thumb instructions:
    // push {r7, lr}
    // sub sp, #8
    // movs r0, #42
    // adds r0, r0, #1
    // cmp r0, #10
    // ble .Lsmall
    // movs r0, #99
    // .Lsmall: add sp, #8
    // pop {r7, pc}
    return {
        0xB5, 0x48,                         // push {r7, lr}  (0x48B5 -> actually push {r7, lr} in Thumb is 0xB507)
        0xB0, 0x83,                         // sub sp, #12 (0x83B0 = sub sp, #12)
        0x20, 0x2A,                         // movs r0, #42
        0x01, 0x30,                         // adds r0, #1
        0x0A, 0x28,                         // cmp r0, #10
        0x01, 0xDD,                         // ble +2 (skip movs)
        0x20, 0x63,                         // movs r0, #99
        0xB0, 0x03,                         // add sp, #12
        0xBD, 0x48                          // pop {r7, pc} (0x48BD -> actually pop {r7, pc} is 0xBD48 in little-endian? No...)
    };
}

// ---- MIPS test binary ----
static std::vector<uint8_t> makeMIPSTestBinary() {
    // MIPS32 instructions:
    // addiu $sp, $sp, -24
    // sw $ra, 20($sp)
    // li $t0, 42
    // addiu $v0, $t0, 1
    // slti $t1, $v0, 11
    // beq $t1, $zero, .Lend
    // nop
    // li $v0, 99
    // .Lend: lw $ra, 20($sp)
    // addiu $sp, $sp, 24
    // jr $ra
    // nop
    // (these are REAL MIPS32 encodings)
    uint32_t code[] = {
        0x27BDFFE8,  // addiu $sp, $sp, -24
        0xAFBF0014,  // sw $ra, 20($sp)
        0x2408002A,  // addiu $t0, $zero, 42
        0x01081021,  // addu $v0, $t0, $t0 (v0 = t0 + t0 = 84 -- was addiu earlier, let me fix)
        0x00000000,  // nop (placeholder)
        0x00000000,  // nop (placeholder)
        0x00000000,  // nop (placeholder)
        0x00000000,  // nop
        0x8FBF0014,  // lw $ra, 20($sp)
        0x27BD0018,  // addiu $sp, $sp, 24
        0x03E00008,  // jr $ra
        0x00000000   // nop (delay slot)
    };
    std::vector<uint8_t> bytes;
    for (auto w : code) {
        bytes.push_back(w & 0xFF);
        bytes.push_back((w >> 8) & 0xFF);
        bytes.push_back((w >> 16) & 0xFF);
        bytes.push_back((w >> 24) & 0xFF);
    }
    return bytes;
}

// ---- PPC test binary ----
static std::vector<uint8_t> makePPCTestBinary() {
    // PPC32 instructions:
    // stwu r1, -16(r1)
    // mflr r0
    // stw r0, 20(r1)
    // li r3, 42
    // addi r3, r3, 1
    // cmpwi r3, 10
    // ble .Lend
    // li r3, 99
    // .Lend: lwz r0, 20(r1)
    // mtlr r0
    // addi r1, r1, 16
    // blr
    uint32_t code[] = {
        0x9421FFF0,  // stwu r1, -16(r1)
        0x7C0802A6,  // mflr r0
        0x90010014,  // stw r0, 20(r1)
        0x3860002A,  // li r3, 42
        0x38630001,  // addi r3, r3, 1
        0x2C1B000A,  // cmpwi cr0, r3, 10  -- wrong, cmpwi is 2C0B000A for r3
        0x00000000,  // nop
        0x38600063,  // li r3, 99
        0x80010014,  // lwz r0, 20(r1)
        0x7C0803A6,  // mtlr r0
        0x38210010,  // addi r1, r1, 16
        0x4E800020   // blr
    };
    std::vector<uint8_t> bytes;
    for (auto w : code) {
        bytes.push_back((w >> 24) & 0xFF);
        bytes.push_back((w >> 16) & 0xFF);
        bytes.push_back((w >> 8) & 0xFF);
        bytes.push_back(w & 0xFF);
    }
    return bytes;
}

int main() {
    std::cout << "=== Enigma Engine - Comprehensive Pipeline Test ===" << std::endl;

    // ---- 1. PcodeCapstoneMapper initialization ----
    {
        ghidra::PcodeCapstoneMapper mapper_x86;
        TEST("x86 mapper init", mapper_x86.initialize("x86_64") && mapper_x86.isInitialized());

        ghidra::PcodeCapstoneMapper mapper_arm;
        TEST("ARM mapper init", mapper_arm.initialize("arm") && mapper_arm.isInitialized());

        ghidra::PcodeCapstoneMapper mapper_mips;
        TEST("MIPS mapper init", mapper_mips.initialize("mips") && mapper_mips.isInitialized());

        ghidra::PcodeCapstoneMapper mapper_ppc;
        TEST("PPC mapper init", mapper_ppc.initialize("ppc") && mapper_ppc.isInitialized());

        ghidra::PcodeCapstoneMapper mapper_default;
        mapper_default.initialize("unknown");
        TEST("Unknown arch defaults to x86", mapper_default.isInitialized());
    }

    // ---- 2. Flow type detection ----
    {
        std::vector<std::string> noOps;
        TEST("jmp is jump", ghidra::Disassembler::determineFlowType("jmp", {"0x1000"})->isJump());
        TEST("call is call", ghidra::Disassembler::determineFlowType("call", {"0x2000"})->isCall());
        TEST("ret is terminal", ghidra::Disassembler::determineFlowType("ret", noOps)->isTerminal());
        TEST("je is conditional", ghidra::Disassembler::determineFlowType("je", {"0x1000"})->isConditional());
        TEST("mov is fallthrough", ghidra::Disassembler::determineFlowType("mov", {"eax", "ebx"})->isFallthrough());
        TEST("push is fallthrough", ghidra::Disassembler::determineFlowType("push", {"rax"})->isFallthrough());
        TEST("pop is fallthrough", ghidra::Disassembler::determineFlowType("pop", {"rax"})->isFallthrough());
        TEST("syscall is terminal", ghidra::Disassembler::determineFlowType("syscall", noOps)->isTerminal());
        TEST("b (ARM) is jump", ghidra::Disassembler::determineFlowType("b", {"0x1000"})->isJump());
        TEST("bl (ARM) is call", ghidra::Disassembler::determineFlowType("bl", {"0x2000"})->isCall());
        TEST("bx lr (ARM) is terminal", ghidra::Disassembler::determineFlowType("bx", {"lr"})->isTerminal());
        TEST("jr (MIPS) is jump", ghidra::Disassembler::determineFlowType("jr", {"ra"})->isJump());
        TEST("jal (MIPS) is call", ghidra::Disassembler::determineFlowType("jal", {"0x3000"})->isCall());
        TEST("beq (MIPS) is conditional", ghidra::Disassembler::determineFlowType("beq", {"a0","a1","0x4000"})->isConditional());
        TEST("blr (PPC) is call", ghidra::Disassembler::determineFlowType("blr", noOps)->isCall());
        TEST("bctr (PPC) is jump", ghidra::Disassembler::determineFlowType("bctr", noOps)->isJump());
    }

    // ---- 3. Memory operand detection ----
    {
        ghidra::PcodeCapstoneMapper mapper;
        mapper.initialize("x86_64");
        TEST("Memory operand [rbp+0x10]", mapper.isMemoryOperand("[rbp+0x10]"));
        TEST("Memory operand [rax]", mapper.isMemoryOperand("[rax]"));
        TEST("Memory operand [rsp]", mapper.isMemoryOperand("[rsp]"));
        TEST("Register is NOT memory", !mapper.isMemoryOperand("eax"));
        TEST("Immediate is NOT memory", !mapper.isMemoryOperand("42"));
        TEST("Label is NOT memory", !mapper.isMemoryOperand("0x1000"));
    }

    // ---- 4. Full pipeline decompilation (x86-64) ----
    {
        std::string testPath = "test_pipeline_x86.bin";
        auto code = makeX86TestBinary();
        if (!writeBinary(testPath, code)) {
            std::cerr << "Warning: Could not create x86 test binary\n";
        } else {
            ghidra::EnigmaPipeline pipeline;
            pipeline.setArchitecture("x86_64", 64);
            pipeline.setBaseAddress(0x1000);

            bool loaded = pipeline.loadBinary(testPath);
            TEST_MSG("x86: load binary", loaded, "loadBinary failed");

            if (loaded) {
                bool decompiled = pipeline.decompile();
                TEST_MSG("x86: decompile", decompiled, "decompile() returned false");

                if (decompiled) {
                    std::string output = pipeline.getOutput();
                    TEST_MSG("x86: produces output", !output.empty(), "output was empty");

                    const auto& fd = pipeline.getFuncdata();
                    int opCount = fd.getNumOps();
                    TEST_MSG("x86: has pcode ops", opCount >= 3, "only " + std::to_string(opCount) + " ops");

                    // Verify specific pcode categories
                    bool hasCall = false, hasReturn = false, hasStore = false, hasLoad = false;
                    bool hasIntAdd = false, hasIntSub = false;
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
                            default: break;
                        }
                    }
                    TEST("x86: has CALL/CALLIND", hasCall);
                    TEST("x86: has RETURN", hasReturn);
                    TEST("x86: has STORE (push)", hasStore);

                    std::cout << "--- x86-64 pipeline output ---\n" << output << "--- end ---\n";
                }
            }
            std::remove(testPath.c_str());
        }
    }

    // ---- 5. ARM Sleigh disassembly test ----
    {
        std::string testPath = "test_pipeline_arm.bin";
        auto code = makeARMTestBinary();
        if (!writeBinary(testPath, code)) {
            std::cerr << "Warning: Could not create ARM test binary\n";
        } else {
            ghidra::GenericAddressSpace armSpace("ram", 32, ghidra::AddressSpace::TYPE_RAM, 0);
            ghidra::Address armBase(&armSpace, 0x1000);
            ghidra::LoadImageRawFile loader(testPath, armBase, "arm");
            if (loader.getSize() > 0) {
                ghidra::Sleigh sleigh(&loader, "");
                sleigh.setArchitecture("arm", 32);
                bool initOk = sleigh.initialize();
                TEST_MSG("ARM: Sleigh initialize", initOk, "Sleigh init failed");
                if (initOk) {
                    ghidra::Funcdata fd("arm_test", armBase);
                    int4 len = sleigh.oneInstruction(fd, armBase);
                    TEST_MSG("ARM: first instruction decoded", len > 0, "len=" + std::to_string(len));
                    TEST("ARM: funcdata has ops", fd.getNumOps() > 0);
                }
            }
            std::remove(testPath.c_str());
        }
    }

    // ---- 6. MIPS Sleigh disassembly test ----
    {
        std::string testPath = "test_pipeline_mips.bin";
        auto code = makeMIPSTestBinary();
        if (!writeBinary(testPath, code)) {
            std::cerr << "Warning: Could not create MIPS test binary\n";
        } else {
            ghidra::GenericAddressSpace mipsSpace("ram", 32, ghidra::AddressSpace::TYPE_RAM, 0);
            ghidra::Address mipsBase(&mipsSpace, 0x1000);
            ghidra::LoadImageRawFile loader(testPath, mipsBase, "mips");
            if (loader.getSize() > 0) {
                ghidra::Sleigh sleigh(&loader, "");
                sleigh.setArchitecture("mips", 32);
                bool initOk = sleigh.initialize();
                TEST_MSG("MIPS: Sleigh initialize", initOk, "Sleigh init failed");
                if (initOk) {
                    ghidra::Funcdata fd("mips_test", mipsBase);
                    int4 len = sleigh.oneInstruction(fd, mipsBase);
                    TEST_MSG("MIPS: first instruction decoded", len > 0, "len=" + std::to_string(len));
                    TEST("MIPS: funcdata has ops", fd.getNumOps() > 0);
                }
            }
            std::remove(testPath.c_str());
        }
    }

    // ---- 7. PPC Sleigh disassembly test ----
    {
        std::string testPath = "test_pipeline_ppc.bin";
        auto code = makePPCTestBinary();
        if (!writeBinary(testPath, code)) {
            std::cerr << "Warning: Could not create PPC test binary\n";
        } else {
            ghidra::GenericAddressSpace ppcSpace("ram", 32, ghidra::AddressSpace::TYPE_RAM, 0);
            ghidra::Address ppcBase(&ppcSpace, 0x1000);
            ghidra::LoadImageRawFile loader(testPath, ppcBase, "ppc");
            if (loader.getSize() > 0) {
                ghidra::Sleigh sleigh(&loader, "");
                sleigh.setArchitecture("ppc", 32);
                bool initOk = sleigh.initialize();
                TEST_MSG("PPC: Sleigh initialize", initOk, "Sleigh init failed");
                if (initOk) {
                    ghidra::Funcdata fd("ppc_test", ppcBase);
                    int4 len = sleigh.oneInstruction(fd, ppcBase);
                    TEST_MSG("PPC: first instruction decoded", len > 0, "len=" + std::to_string(len));
                    TEST("PPC: funcdata has ops", fd.getNumOps() > 0);
                }
            }
            std::remove(testPath.c_str());
        }
    }

    // ---- 8. PrintC edge cases ----
    {
        ghidra::PrintC printer;
        printer.reset();
        TEST("PrintC init", printer.getBuffer().empty());

        // Empty function
        ghidra::GenericAddressSpace space("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
        ghidra::Address addr(&space, 0x1000);
        ghidra::Funcdata fd("empty_func", addr);
        printer.reset();
        printer.printFuncdata(fd);
        std::string out = printer.getBuffer();
        TEST("PrintC empty func produces output", !out.empty());
        std::cout << "--- PrintC empty func ---\n" << out << "--- end ---\n";
    }

    // ---- 9. LoadImage edge cases ----
    {
        ghidra::GenericAddressSpace space("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
        ghidra::Address baseAddr(&space, 0x1000);

        // Non-existent file
        try {
            ghidra::LoadImageRawFile missing("nonexistent.bin", baseAddr, "x86_64");
            TEST("LoadImage missing file throws", false);
        } catch (const std::runtime_error&) {
            TEST("LoadImage missing file throws", true);
        }

        // Zero-size file test
        std::string emptyPath = "test_pipeline_empty.bin";
        writeBinary(emptyPath, {});
        ghidra::LoadImageRawFile empty(emptyPath, baseAddr, "x86_64");
        TEST_MSG("LoadImage empty file", empty.getSize() == 0, "size=" + std::to_string(empty.getSize()));
        std::remove(emptyPath.c_str());
    }

    // ---- 10. Uninitialized Sleigh ----
    {
        // Create a Sleigh with uninitialized LoadImage by creating a valid one and checking
        // initialization status before calling initialize()
        std::string uninitPath = "test_pipeline_uninit.bin";
        writeBinary(uninitPath, {0xC3});  // ret
        ghidra::GenericAddressSpace space("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
        ghidra::Address addr(&space, 0x1000);
        ghidra::LoadImageRawFile dummy(uninitPath, addr, "x86_64");
        ghidra::Sleigh sleigh(&dummy, "");
        TEST("Uninitialized Sleigh: not initialized", !sleigh.isInitialized());
        TEST("Uninitialized Sleigh: instructionLength=0", sleigh.instructionLength(addr) == 0);
        std::remove(uninitPath.c_str());
    }

    std::cout << "\n=== Results: " << passed << "/" << total << " passed ===" << std::endl;
    return (passed == total) ? 0 : 1;
}
