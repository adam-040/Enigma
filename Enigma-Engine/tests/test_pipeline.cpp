/**
 * Enigma Engine - Pipeline Integration Test
 * Tests the full Enigma-native pipeline: binary load -> disassemble -> pcode -> PrintC
 */
#include <ghidra/EnigmaPipeline.h>
#include <ghidra/PcodeCapstoneMapper.h>
#include <ghidra/Disassembler.h>
#include <ghidra/Funcdata.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/OpCode.h>
#include <ghidra/PrintC.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/BlockGraph.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <cstdio>

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

// Create a temporary x86-64 binary file with known instructions
static bool createTestBinary(const std::string& path) {
    // Raw x86-64 machine code for:
    // 0x1000: push rbp
    // 0x1001: mov rbp, rsp
    // 0x1004: mov eax, 42
    // 0x1009: add eax, 1
    // 0x100c: pop rbp
    // 0x100d: call 0x1020
    // 0x1012: ret
    uint8_t code[] = {
        0x55,                                           // push rbp
        0x48, 0x89, 0xE5,                               // mov rbp, rsp
        0xB8, 0x2A, 0x00, 0x00, 0x00,                   // mov eax, 42
        0x83, 0xC0, 0x01,                               // add eax, 1
        0x5D,                                           // pop rbp
        0xE8, 0x0E, 0x00, 0x00, 0x00,                   // call 0x1020 (relative offset = 0x1020 - 0x1012 = 0x0E)
        0xC3                                            // ret
    };

    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    size_t written = std::fwrite(code, 1, sizeof(code), f);
    std::fclose(f);
    return written == sizeof(code);
}

int main() {
    std::cout << "=== Enigma Engine - Pipeline Integration Test ===" << std::endl;

    // ---- Test 1: PcodeCapstoneMapper basic mapping ----
    {
        ghidra::PcodeCapstoneMapper mapper;
        TEST("Mapper initially not initialized", !mapper.isInitialized());

        bool initOk = mapper.initialize("x86_64");
        TEST("Mapper initialize x86_64", initOk && mapper.isInitialized());
    }

    // ---- Test 2: DisassembledInstruction flow type detection ----
    {
        std::vector<std::string> noOperands;
        TEST("JMP flow", ghidra::Disassembler::determineFlowType("jmp", {"0x1000"})->isJump());
        TEST("CALL flow", ghidra::Disassembler::determineFlowType("call", {"0x2000"})->isCall());
        TEST("RET flow",  ghidra::Disassembler::determineFlowType("ret", noOperands)->isTerminal());
        TEST("JE flow",   ghidra::Disassembler::determineFlowType("je", {"0x1000"})->isConditional());
        TEST("MOV flow",  ghidra::Disassembler::determineFlowType("mov", {"eax", "ebx"})->isFallthrough());
    }

    // ---- Test 3: Pipeline decompilation of test binary ----
    {
        std::string testPath = "test_pipeline_binary.bin";
        if (!createTestBinary(testPath)) {
            std::cerr << "Warning: Could not create test binary, skipping pipeline test\n";
        } else {
            ghidra::EnigmaPipeline pipeline;
            pipeline.setArchitecture("x86_64", 64);
            pipeline.setBaseAddress(0x1000);

            bool loaded = pipeline.loadBinary(testPath);
            TEST("Pipeline load binary", loaded);

            if (loaded) {
                bool decompiled = pipeline.decompile();
                TEST("Pipeline decompile", decompiled);

                if (decompiled) {
                    std::string output = pipeline.getOutput();
                    TEST("Pipeline produces output", !output.empty());
                    std::cout << "--- Pipeline output ---\n" << output << "--- end ---\n";

                    // Check that Funcdata has ops created
                    const auto& fd = pipeline.getFuncdata();
                    TEST("Funcdata has ops", fd.getNumOps() > 0);

                    // Verify that specific pcode opcodes are present by checking op list
                    // With optimizations: constant folding eliminates INT_ADD, DCE removes dead COPY/ADD chains
                    bool hasCall = false, hasReturn = false, hasStore = false;
                    int copyCount = 0, addCount = 0;
                    for (int i = 0; i < fd.getNumOps(); i++) {
                        auto* op = fd.getOp(i);
                        if (!op) continue;
                        if (op->getOpcode() == ghidra::PcodeOp::CALL ||
                            op->getOpcode() == ghidra::PcodeOp::CALLIND) hasCall = true;
                        if (op->getOpcode() == ghidra::PcodeOp::RETURN) hasReturn = true;
                        if (op->getOpcode() == ghidra::PcodeOp::STORE) hasStore = true;
                        if (op->getOpcode() == ghidra::PcodeOp::COPY) copyCount++;
                        if (op->getOpcode() == ghidra::PcodeOp::INT_ADD) addCount++;
                    }
                    TEST("Pcode has CALL/CALLIND ops", hasCall);
                    TEST("Pcode has RETURN op", hasReturn);
                    TEST("Pcode has STORE op", hasStore);
                    // INT_ADD from 'add eax, 1' should be constant-folded away
                    TEST("Constant folding eliminated INT_ADD", addCount == 0);
                    // Redundant COPY chains eliminated
                    TEST("Redundant COPY ops minimized", copyCount <= 2);
                }
            }

            std::remove(testPath.c_str());
        }
    }

    // ---- Test 4: PrintC generates valid output ----
    {
        ghidra::PrintC printer;
        printer.reset();
        TEST("PrintC initializes", printer.getBuffer().empty());

        // Create a simple Funcdata with known ops and print it
        ghidra::GenericAddressSpace testSpace("ram", 64, ghidra::AddressSpace::TYPE_RAM, 0);
        ghidra::Address testAddr(&testSpace, 0x1000);
        ghidra::Funcdata fd("test_func", testAddr);

        // Create some varnodes and ops
        ghidra::VarnodeAST* vn1 = fd.createVarnode(ghidra::Address(&testSpace, 0x2000), 4, 1);
        ghidra::VarnodeAST* vn2 = fd.createVarnode(ghidra::Address(&testSpace, 0x2004), 4, 2);
        ghidra::VarnodeAST* result = fd.createVarnode(ghidra::Address(&testSpace, 0x2008), 4, 3);

        ghidra::PcodeOpAST* op = fd.createOp(testAddr, ghidra::PcodeOp::COPY, 1);
        op->setOutput(vn1);
        op->setInput(vn2, 0);

        auto* block = fd.getBlockGraph()->addBlock();
        fd.getBlockGraph()->setStartNode(0);
        block->insertEnd(op);

        printer.reset();
        printer.printFuncdata(fd);
        std::string output = printer.getBuffer();

        TEST("PrintC produces output for Funcdata", !output.empty());
        std::cout << "--- PrintC test output ---\n" << output << "--- end ---\n";
    }

    std::cout << "\n=== Results: " << passed << "/" << total << " passed ===" << std::endl;
    return (passed == total) ? 0 : 1;
}
