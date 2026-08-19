// Diagnostic probe: import a Ghidra project (.rep / .gzf / .gbf) and dump
// the resulting ProgramDB state for fidelity forensics:
//   - program metadata (language, compiler, effective image base)
//   - memory blocks (name, start address, length)
//   - function inventory (address, name) and count
//   - optional: field-by-field dump of one function (signature, params,
//     locals, storage) plus its decompilation
// Usage: enigma_gzf_probe <db.gbf | dir.rep | file.gzf> [funcName]

#include <ghidra/import/RepProject.h>
#include <ghidra/import/GbfReader.h>
#include <ghidra/import/GzfProgramImporter.h>
#include <ghidra/DecompInterface.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionSignature.h>
#include <ghidra/Memory.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Variable.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/DataType.h>

#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace ghidra;

namespace {

void printAddress(const char* label, const Address& a) {
    std::cout << label << "=0x" << std::hex << a.getOffset() << std::dec << "\n";
}

void dumpFunction(Function* fn, const std::string& label) {
    std::cout << "  " << label << ":\n";
    printAddress("    entry", fn->getEntryPoint());
    std::cout << "    name=" << fn->getName()
              << " sig=\"" << fn->getSignatureString() << "\""
              << " convention="
              << (fn->getCallingConvention() ? fn->getCallingConvention()->getName() : "null")
              << "\n";
    DataType* ret = fn->getReturnType();
    std::cout << "    returnType=" << (ret ? ret->getName() : "null")
              << " params=" << fn->getParameters().size()
              << " locals=" << fn->getLocalVariables().size() << "\n";
    for (const Variable* p : fn->getParameters()) {
        std::cout << "    param name=" << p->getName()
                  << " type=" << (p->getDataType() ? p->getDataType()->getName() : "null");
        const VariableStorage& st = p->getVariableStorage();
        if (st.isStackStorage()) {
            std::cout << " storage=stack:" << st.getStackOffset();
        } else if (st.isRegisterStorage()) {
            std::cout << " storage=reg";
            for (Register* r : st.getRegisters()) {
                std::cout << ":" << r->getName();
            }
        } else {
            std::cout << " storage=unknown";
        }
        std::cout << "\n";
    }
    for (const Variable* l : fn->getLocalVariables()) {
        std::cout << "    local name=" << l->getName()
                  << " type=" << (l->getDataType() ? l->getDataType()->getName() : "null");
        if (l->hasStackStorage()) {
            std::cout << " storage=stack:" << l->getStackOffset();
        } else if (l->hasAssignedStorage()) {
            std::cout << " storage=assigned";
        }
        std::cout << "\n";
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: enigma_gzf_probe <db.gbf | dir.rep | file.gzf> [funcName]\n"
                     "                        [--instr HEXADDR]\n";
        return 1;
    }
    const std::string source = argv[1];
    const std::string wantFunc = argc > 2 ? argv[2] : "";
    std::string instrAddr;
    for (int i = 3; i < argc; i++) {
        if (std::string(argv[i]) == "--instr" && i + 1 < argc) {
            instrAddr = argv[++i];
        }
    }

    try {
        std::vector<uint8_t> dbBytes;
        std::string programName;
        const std::string src = source;
        if (GbfReader::isGbfFile(src)) {
            std::ifstream f(src, std::ios::binary);
            if (!f) {
                std::cerr << "cannot open: " << src << "\n";
                return 1;
            }
            dbBytes.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
            size_t pos = src.find_last_of("/\\");
            programName = pos == std::string::npos ? src : src.substr(pos + 1);
            pos = programName.find_last_of('.');
            if (pos != std::string::npos) {
                programName = programName.substr(0, pos);
            }
        } else {
            RepProject proj(src);
            const auto& progs = proj.programs();
            if (progs.empty()) {
                std::cerr << "no programs in project\n";
                return 1;
            }
            programName = progs[0].name;
            dbBytes = proj.getDatabaseBytes(progs[0]);
        }
        if (dbBytes.empty()) {
            std::cerr << "no database bytes\n";
            return 1;
        }

        std::unique_ptr<GbfReader> reader = GbfReader::fromMemory(std::move(dbBytes));
        GzfProgramImporter importer(*reader);
        std::unique_ptr<ProgramDB> program = importer.import(programName);

        std::cout << "== imported program: " << programName << " ==\n";
        std::cout << "language=" << program->getLanguageID().getIdAsString() << "\n";
        std::cout << "compilerSpec=" << program->getCompilerSpecID().getIdAsString() << "\n";
        printAddress("effectiveImageBase", program->getEffectiveImageBase());

        std::cout << "\n== memory blocks ==\n";
        for (MemoryBlock* b : program->getMemory()->getBlocks()) {
            std::cout << "  " << b->getName() << " start=0x" << std::hex
                      << b->getStart().getOffset() << std::dec << " length=" << b->getSize()
                      << (b->isExecute() ? " X" : "") << (b->isWrite() ? " W" : "")
                      << (b->isRead() ? " R" : "") << "\n";
        }

        FunctionManager* fm = program->getFunctionManager();
        std::cout << "\n== functions (" << fm->getFunctionCount() << ") ==\n";
        Function* target = nullptr;
        int count = 0;
        for (FunctionIterator it = fm->getFunctions(true); it.hasNext();) {
            Function* fn = it.next();
            std::cout << "  0x" << std::hex << fn->getEntryPoint().getOffset() << std::dec
                      << "  " << fn->getName() << "\n";
            count++;
            if (!wantFunc.empty() && fn->getName() == wantFunc) {
                target = fn;
            }
        }
        std::cout << "  ... total " << count << " functions\n";

        if (target) {
            std::cout << "\n== function fields: " << wantFunc << " ==\n";
            dumpFunction(target, "imported");
            DecompInterface decomp;
            decomp.openProgram(program.get());
            DecompileResults res = decomp.decompileFunction(target, nullptr);
            std::cout << "\n== decompiled (imported) ==\n";
            std::cout << (res.decompiled ? res.cCode : "<decompile failed>") << "\n";
        } else if (!wantFunc.empty()) {
            std::cout << "\nfunction not found: " << wantFunc << "\n";
        }

        if (!instrAddr.empty()) {
            DecompInterface decomp;
            decomp.openProgram(program.get());
            uint64_t addr = std::stoull(instrAddr, nullptr, 16);
            Address a(const_cast<AddressSpace*>(
                          program->getAddressFactory()->getDefaultAddressSpace()),
                      static_cast<int64_t>(addr));
            Listing* listing = program->getListing();
            Instruction* inst = listing->getInstructionAt(a);
            std::cout << "\n== listing lookup at 0x" << std::hex << addr << std::dec << " ==\n";
            std::cout << "instruction=" << (inst ? inst->getMnemonicString() : "<null>")
                      << " count=" << listing->getInstructionCount() << "\n";
            int shown = 0;
            for (Instruction* i : listing->getAllInstructions()) {
                uint64_t off = static_cast<uint64_t>(i->getAddress().getOffset());
                if (shown < 8) {
                    std::cout << "  first 0x" << std::hex << off << std::dec << " "
                              << i->getMnemonicString() << "\n";
                }
                if (off >= 0x1400014e0 && off <= 0x140001520) {
                    std::cout << "  stored 0x" << std::hex << off << std::dec << " "
                              << i->getMnemonicString() << "\n";
                }
                shown++;
            }
            Data* d0 = listing->getDataAt(Address(const_cast<AddressSpace*>(
                        program->getAddressFactory()->getDefaultAddressSpace()), 0x140013000));
            Data* d1 = listing->getDataAt(Address(const_cast<AddressSpace*>(
                        program->getAddressFactory()->getDefaultAddressSpace()), 0x140013019));
            std::cout << "data13000=" << (d0 ? std::to_string(d0->getLength()) : "<null>")
                      << " data13019=" << (d1 ? std::to_string(d1->getLength()) : "<null>")
                      << " dataCount=" << listing->getDataCount() << "\n";
            std::cout << "\n== instructions at 0x" << std::hex << addr << std::dec
                      << " ==\n" << decomp.disassembleAt(a, 40) << "\n";
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}