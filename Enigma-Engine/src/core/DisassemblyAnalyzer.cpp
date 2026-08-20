#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Disassembler.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <algorithm>
#include <sstream>
#include <cstdio>

namespace ghidra {

DisassemblyAnalyzer::DisassemblyAnalyzer()
    : AbstractAnalyzer("Disassembly",
                       "Recursive-descent disassembly of entry points, following calls and branches.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY);
    setDefaultEnablement(true);
}

static bool parseHexOperand(const std::string& op, uint64_t& out) {
    std::string s = op;
    while (!s.empty() && (s[0] == ' ' || s[0] == '\t')) s.erase(s.begin());
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s = s.substr(2);
    } else {
        for (char c : s) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
        }
    }
    if (s.empty()) return false;
    try {
        out = std::stoull(s, nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

bool DisassemblyAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getMemory() && program->getAddressFactory() &&
           program->getMemory()->getBlocks().size() > 0;
}

bool DisassemblyAnalyzer::added(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    auto* mem = program->getMemory();
    auto* listing = program->getListing();
    auto* addrFactory = program->getAddressFactory();
    if (!mem || !listing || !addrFactory) return false;

    auto* codeSpace = const_cast<AddressSpace*>(addrFactory->getDefaultAddressSpace());
    if (!codeSpace) return false;

    // Infer architecture from program language
    std::string arch = "x86";
    int bitness = 32;
    bool bigEndian = false;
    {
        LanguageID lid = program->getLanguageID();
        std::string lidStr = lid.getIdAsString();
        if (lidStr.find("x86") != std::string::npos || lidStr.find("i386") != std::string::npos)
            arch = "x86";
        else if (lidStr.find("AARCH64") != std::string::npos) arch = "aarch64";
        else if (lidStr.find("ARM") != std::string::npos) arch = "arm";
        else if (lidStr.find("MIPS") != std::string::npos) arch = "mips";
        else if (lidStr.find("PowerPC") != std::string::npos) arch = "ppc";
        if (lidStr.find(":BE:") != std::string::npos)
            bigEndian = true;
        if (lidStr.find("64") != std::string::npos)
            bitness = 64;
        else if (lidStr == "unknown" && addrFactory->getDefaultAddressSpace()) {
            auto* defSpace = addrFactory->getDefaultAddressSpace();
            if (defSpace->getSize() > 32)
                bitness = 64;
        }
    }

    auto disassembler = createDisassembler(arch, bitness, bigEndian);
    if (!disassembler) return false;

    // Build initial work queue from ProgramDB
    std::queue<uint64_t> workQueue;
    std::unordered_set<uint64_t> visited;
    std::unordered_set<uint64_t> functionEntryPoints;

    auto addEntry = [&](uint64_t ea, bool isFuncStart) {
        if (ea == 0) return;
        if (isFuncStart) {
            functionEntryPoints.insert(ea);
        }
        if (visited.find(ea) != visited.end()) return;
        Address testAddr(codeSpace, static_cast<int64_t>(ea));
        MemoryBlock* block = mem->getBlock(testAddr);
        if (!block) {
            log.append("DisassemblyAnalyzer: entry 0x" + std::to_string(ea) + " not in memory");
            return;
        }
        // PHASE 2 FIX: do not enqueue non-executable addresses (prevents descent into .rdata/.data)
        if (!block->isExecute()) {
            log.append("DisassemblyAnalyzer: entry 0x" + std::to_string(ea) + " not executable");
            return;
        }
        visited.insert(ea);
        workQueue.push(ea);
    };

    // 1. Existing functions (e.g., "entry" from populateProgram)
    auto* funcMgr = program->getFunctionManager();
    if (funcMgr) {
        FunctionIterator fit = funcMgr->getFunctions(true);
        while (fit.hasNext()) {
            Function* f = fit.next();
            if (f) { addEntry(static_cast<uint64_t>(f->getEntryPoint().getOffset()), true); }
        }
    }

    // 2. External entry points from symbol table
    auto* symTable = program->getSymbolTable();
    if (symTable) {
        auto extPoints = symTable->getExternalEntryPoints();
        for (const Address& ea : extPoints) {
            addEntry(static_cast<uint64_t>(ea.getOffset()), true);
        }
    }

    // 3. Import thunks from external manager
    auto* extMgr = program->getExternalManager();
    if (extMgr && extMgr->getExternalLocationCount() > 0) {
        auto locs = extMgr->getExternalLocations();
        for (auto* loc : locs) {
            if (loc) {
                Address locAddr = loc->getAddress();
                if (locAddr.isValid())
                    { addEntry(static_cast<uint64_t>(locAddr.getOffset()), true); }
            }
        }
    }

    // BFS recursive descent disassembly
    uint64_t totalInstructions = 0;
    uint64_t totalEntries = workQueue.size();
    uint64_t nextLogEntry = 1000;
    uint64_t nextLogInstr = 100000;
    std::vector<uint8_t> readBuf(16);

    while (!workQueue.empty()) {
        if (monitor && monitor->isCancelled()) break;

        uint64_t currentAddr = workQueue.front();
        workQueue.pop();

        // Re-check visited (might have been added from another path)
        if (visited.find(currentAddr) == visited.end()) continue;

        // Linear decode from this address until flow terminates
        const int MAX_LINEAR = 100000;

        for (int linearCount = 0; linearCount < MAX_LINEAR; ++linearCount) {
            if (monitor && monitor->isCancelled()) break;

            // Check if instruction already exists at this address
            Address instAddr(codeSpace, static_cast<int64_t>(currentAddr));
            if (listing->getInstructionAt(instAddr)) {
                break;  // Already decoded in another path
            }

            // Verify address is in executable memory
            {
                MemoryBlock* block = mem->getBlock(instAddr);
                if (!block || !block->isExecute()) {
                    // PHASE 2 FIX: stop linear decode when leaving executable section
                    break;
                }
            }

            // Create function at the start of this linear run
            if (linearCount == 0) {
                if (funcMgr && functionEntryPoints.count(currentAddr) && !funcMgr->getFunctionAt(instAddr) && !funcMgr->getFunctionContaining(instAddr)) {
                    MemoryBlock* block = mem->getBlock(instAddr);
                    // PHASE 2 FIX: only create functions in executable sections
                    if (block && block->isExecute()) {
                        AddressSet body(instAddr, instAddr);
                        funcMgr->createFunction("", instAddr, body, SourceType::ANALYSIS);
                    }
                }
            }

            // Read bytes
            int got = mem->getBytes(instAddr, readBuf.data(), static_cast<int>(readBuf.size()));
            if (got <= 0) break;

            std::vector<uint8_t> bytes(readBuf.begin(), readBuf.begin() + got);
            DisassembledInstruction di = disassembler->disassembleOne(bytes, currentAddr);
            if (di.length <= 0) break;

            // Create ProgramDB Instruction
            auto* inst = new Instruction(program, instAddr, di.mnemonic, di.length, di.flowType);
            for (size_t oi = 0; oi < di.operands.size(); ++oi) {
                inst->setOperand(static_cast<int>(oi), di.operands[oi]);
            }
            // Propagate decoded operand scalars (ownership transfers to Instruction)
            for (size_t oi = 0; oi < di.operandScalars.size(); ++oi) {
                for (auto& scalar : di.operandScalars[oi]) {
                    if (scalar) {
                        inst->addOperandScalar(static_cast<int>(oi), scalar.release());
                    }
                }
            }
            listing->addInstruction(inst);
            ++totalInstructions;

            if (totalInstructions >= nextLogInstr) {
                std::cerr << "[INFO] DisassemblyAnalyzer: " << totalInstructions
                    << " instructions decoded, " << workQueue.size() << " entries remaining" << std::endl;
                nextLogInstr += 100000;
            }

            // Log first 20 instructions to main debug file
            if (totalInstructions <= 20) {
                const char* dbgPath = getenv("DBG_LOG");
                if (dbgPath) {
                    if (FILE* f = fopen(dbgPath, "a")) {
                        fprintf(f, "[DISASM] 0x%llx: %s", (unsigned long long)instAddr.getOffset(), di.mnemonic.c_str());
                        for (auto& op : di.operands) fprintf(f, " %s", op.c_str());
                        fprintf(f, " (flow=%s)\n", di.flowType ? di.flowType->getName().c_str() : "null");
                        fclose(f);
                    }
                }
            }

            FlowType* ft = di.flowType;
            uint64_t nextOffset = currentAddr + di.length;

            // --- CALL (direct) ---
            if (ft->isCall() && !ft->isComputed()) {
                if (!di.operands.empty()) {
                    uint64_t target = 0;
                    if (parseHexOperand(di.operands[0], target) && target != 0) {
                        Address targetAddr(codeSpace, static_cast<int64_t>(target));
                        inst->addOperandReference(0, targetAddr, &RefTypes::UNCONDITIONAL_CALL,
                                                  SourceType::ANALYSIS);
                        // Mark as function entry — actual createFunction happens when popped
                        addEntry(target, true);
                    }
                }
                // Call continues at next instruction
                currentAddr = nextOffset;
                continue;
            }
            // --- DIRECT JUMP ---
            else if (ft->isJump() && !ft->isComputed()) {
                uint64_t target = 0;
                if (!di.operands.empty() && parseHexOperand(di.operands[0], target) && target != 0) {
                    Address targetAddr(codeSpace, static_cast<int64_t>(target));
                    auto refType = ft->isConditional() ? &RefTypes::CONDITIONAL_JUMP : &RefTypes::UNCONDITIONAL_JUMP;
                    inst->addOperandReference(0, targetAddr, refType, SourceType::ANALYSIS);
                    addEntry(target, false);
                }
                if (ft->isConditional()) {
                    // Follow fallthrough too
                    currentAddr = nextOffset;
                    continue;
                } else {
                    // Unconditional jump — linear path ends here
                    break;
                }
            }
            // --- RETURN / TERMINAL ---
            else if (ft->isTerminal()) {
                break;
            }
            // --- INDIRECT CALL/JUMP ---
            else if (ft->isComputed()) {
                if (ft->hasFallthrough()) {
                    currentAddr = nextOffset;
                    continue;
                } else {
                    break;
                }
            }
            // --- FALLTHROUGH (regular instruction) ---
            else {
                currentAddr = nextOffset;
                continue;
            }
        }
    }

    if (monitor) {
        std::ostringstream msg;
        msg << "Disassembly: " << totalInstructions << " instructions, "
            << visited.size() << " unique addresses enqueued";
        log.append(msg.str());
    }

    return true;
}

} // namespace ghidra
