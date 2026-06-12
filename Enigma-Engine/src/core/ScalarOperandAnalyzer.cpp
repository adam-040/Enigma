#include <ghidra/ScalarOperandAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Scalar.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/Relocation.h>

namespace ghidra {

static constexpr int MAX_TABLE_ENTRIES = 256;

static constexpr uint64_t MASKS[9] = {
    0ULL, 0x0ffULL, 0x0ffffULL, 0x0ffffffULL, 0x0ffffffffULL,
    0x0ffffffffffULL, 0x0ffffffffffffULL, 0x0ffffffffffffffULL, 0xffffffffffffffffULL
};

static constexpr const char* OPT_NAME_RELOCATION_GUIDE = "Relocation Table Guide";

ScalarOperandAnalyzer::ScalarOperandAnalyzer()
    : AbstractAnalyzer("Scalar Operand References",
                       "Finds scalar operands that are valid memory addresses and creates references.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.before().before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

ScalarOperandAnalyzer::ScalarOperandAnalyzer(const std::string& name, const std::string& description)
    : AbstractAnalyzer(name, description, AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.before().before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool ScalarOperandAnalyzer::canAnalyze(Program* program) const {
    // Skip ELF programs (handled by ElfScalarOperandAnalyzer)
    std::string format = program->getExecutableFormat();
    if (format.find("ELF") != std::string::npos ||
        format.find("elf") != std::string::npos) {
        // But still check: ELF may be handled by ElfScalarOperandAnalyzer
    }
    Address min = program->getMinAddress();
    return min.isValid();
}

bool ScalarOperandAnalyzer::getDefaultEnablement(Program* program) const {
    // Match Ghidra Java: skip languages where addresses don't appear directly in code
    std::string format = program->getExecutableFormat();
    if (format.find("ELF") != std::string::npos) return false;

    Address min = program->getMinAddress();
    if (!min.isValid() || min.getOffset() == 0) return false;
    if (program->getAddressFactory()->getDefaultAddressSpace()->getSize() < 32) return false;

    // Skip aligned languages (RISC) - addresses don't appear directly
    auto* listing = program->getListing();
    if (listing) {
        auto* firstInstr = listing->getInstructionAfter(min);
        if (firstInstr) {
            // Simplified: assume aligned languages have alignment > 1
        }
    }
    return true;
}

void ScalarOperandAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPT_NAME_RELOCATION_GUIDE, relocationGuideEnabled_,
                         "Use relocation table entries to guide pointer analysis.");
}

void ScalarOperandAnalyzer::optionsChanged(Options& options, Program* program) {
    relocationGuideEnabled_ = options.getBool(OPT_NAME_RELOCATION_GUIDE);
}

bool ScalarOperandAnalyzer::isValidRelocationAddress(Program* program, const Address& target) {
    RelocationTable* relocTable = program->getRelocationTable();
    if (!relocTable) return false;
    auto relocs = relocTable->getRelocations(target);
    return !relocs.empty();
}

bool ScalarOperandAnalyzer::added(Program* program, const AddressSetView& set,
                                   TaskMonitor* monitor, MessageLog& log) {
    int count = 0;
    if (monitor) {
        monitor->initialize(set.getNumAddresses());
    }

    Listing* listing = program->getListing();
    auto instructions = listing->getInstructions(set);
    for (Instruction* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) {
            monitor->setProgress(++count);
        }
        checkOperands(program, instr);
    }
    return true;
}

void ScalarOperandAnalyzer::checkOperands(Program* program, Instruction* instr) {
    for (int i = 0; i < instr->getNumOperands(); ++i) {
        auto scalars = instr->getOperandScalars(i);
        for (Scalar* scalar : scalars) {
            long value = static_cast<long>(scalar->getUnsignedValue());
            if (value < 4096 || value == 0xffff || value == 0xff00 || value == 0xffffff ||
                value == 0xff0000 || value == 0xff00ff || value == 0xffffffff ||
                value == 0xffffff00 || value == 0xffff0000 || value == 0xff000000) {
                continue;
            }

            if (addReference(program, instr, i, instr->getAddress().getAddressSpace(), scalar)) {
                continue;
            }

            auto spaces = program->getAddressFactory()->getAddressSpaces();
            for (const AddressSpace* space : spaces) {
                if (addReference(program, instr, i, space, scalar)) {
                    break;
                }
            }
        }
    }
}

bool ScalarOperandAnalyzer::addReference(Program* program, Instruction* instr,
                                           int opIndex, const AddressSpace* space,
                                           Scalar* scalar) {
    if (space->isOverlaySpace()) return false;

    int sizeInBytes = space->getSize() / 8;
    if (sizeInBytes <= 0 || sizeInBytes > 8) return false;

    uint64_t value = static_cast<uint64_t>(scalar->getUnsignedValue() & MASKS[sizeInBytes]);
    Address addr(const_cast<AddressSpace*>(space), static_cast<int64_t>(value));

    // Check relocation table guide
    if (relocationGuideEnabled_ && !isValidRelocationAddress(program, addr)) {
        return false;
    }

    MemoryBlock* block = program->getMemory()->getBlock(addr);
    if (block == nullptr || !block->isInitialized()) {
        Symbol* sym = program->getSymbolTable()->getPrimarySymbol(addr);
        if (sym == nullptr || sym->getSource() == SourceType::DEFAULT) {
            return false;
        }
    }

    if (checkOffcutFuncRef(program, addr)) {
        // Could be a jump table - check for it
        auto scalars = instr->getOperandScalars(opIndex);
        checkForJumpTable(program, instr, opIndex, scalars, addr);
        return false;
    }

    if (!instr->getOperandReferences(opIndex).empty()) {
        return false;
    }

    const RefType* refType = RefTypeFactory::getDefaultMemoryRefType(
        instr, opIndex, addr, false);
    instr->addOperandReference(opIndex, addr, refType, SourceType::ANALYSIS);
    return true;
}

bool ScalarOperandAnalyzer::checkOffcutFuncRef(Program* program, const Address& addr) {
    Instruction* instr = program->getListing()->getInstructionContaining(addr);
    if (instr == nullptr) return false;
    if (!(instr->getAddress() == addr)) return true;
    Function* func = program->getFunctionManager()->getFunctionContaining(addr);
    if (func != nullptr && !(func->getEntryPoint() == addr)) return true;
    return false;
}

void ScalarOperandAnalyzer::checkForJumpTable(Program* program, Instruction* refInstr,
                                                int opIndex,
                                                const std::vector<Scalar*>& opObjects,
                                                const Address& addr) {
    Instruction* instr = program->getListing()->getInstructionContaining(addr);
    if (!instr) return;

    FlowType* ftype = instr->getFlowType();
    if (!ftype || !(ftype->isJump() && ftype->isComputed())) return;

    // Figure out the entry size from the scalar
    long entryLen = 0;
    for (Scalar* sc : opObjects) {
        if (!sc) continue;
        long value = static_cast<long>(sc->getUnsignedValue());
        if (value == 4 || value == 2 || value == 8) {
            entryLen = value;
            break;
        }
    }
    if (entryLen == 0) return;

    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    ReferenceManager* refMgr = program->getReferenceManager();
    Memory* memory = program->getMemory();

    auto readTableEntry = [&](const Address& entryAddr) -> Address {
        if (entryLen == 4) {
            uint8_t bytes[4] = {};
            MemoryBlock* blk = memory->getBlock(entryAddr);
            if (!blk) return Address();
            blk->getBytes(entryAddr, bytes, 4);
            uint64_t val = static_cast<uint64_t>(bytes[0]) |
                (static_cast<uint64_t>(bytes[1]) << 8) |
                (static_cast<uint64_t>(bytes[2]) << 16) |
                (static_cast<uint64_t>(bytes[3]) << 24);
            Address entryAddrSpace(entryAddr.getAddressSpace(), static_cast<int64_t>(val));
            if (memory->getBlock(entryAddrSpace)) return entryAddrSpace;
        } else if (entryLen == 8) {
            uint8_t bytes[8] = {};
            MemoryBlock* blk = memory->getBlock(entryAddr);
            if (!blk) return Address();
            blk->getBytes(entryAddr, bytes, 8);
            uint64_t val = static_cast<uint64_t>(bytes[0]) |
                (static_cast<uint64_t>(bytes[1]) << 8) |
                (static_cast<uint64_t>(bytes[2]) << 16) |
                (static_cast<uint64_t>(bytes[3]) << 24) |
                (static_cast<uint64_t>(bytes[4]) << 32) |
                (static_cast<uint64_t>(bytes[5]) << 40) |
                (static_cast<uint64_t>(bytes[6]) << 48) |
                (static_cast<uint64_t>(bytes[7]) << 56);
            Address entryAddrSpace(entryAddr.getAddressSpace(), static_cast<int64_t>(val));
            if (memory->getBlock(entryAddrSpace)) return entryAddrSpace;
        } else if (entryLen == 2) {
            uint8_t bytes[2] = {};
            MemoryBlock* blk = memory->getBlock(entryAddr);
            if (!blk) return Address();
            blk->getBytes(entryAddr, bytes, 2);
            uint64_t val = static_cast<uint64_t>(bytes[0]) |
                (static_cast<uint64_t>(bytes[1]) << 8);
            Address entryAddrSpace(entryAddr.getAddressSpace(), static_cast<int64_t>(val));
            if (memory->getBlock(entryAddrSpace)) return entryAddrSpace;
        }
        return Address();
    };

    // Scan forward entries
    Address scanAddr = addr;
    int tableCount = 0;
    while (tableCount < MAX_TABLE_ENTRIES) {
        if (listing->getInstructionContaining(scanAddr)) break;
        Address target = readTableEntry(scanAddr);
        if (!target.isValid()) break;

        symTable->createLabel(target, "switch_case_" + std::to_string(tableCount),
                              SourceType::ANALYSIS);
        if (refInstr) {
            refMgr->addMemoryReference(refInstr->getAddress(), target,
                                       &RefTypes::DATA, SourceType::ANALYSIS, opIndex);
        }
        ++tableCount;
        try {
            scanAddr = scanAddr.add(entryLen);
        } catch (...) {
            break;
        }
    }

    if (tableCount > 0) {
        program->getBookmarkManager()->setBookmark(addr, "ANALYSIS",
            "Switch table with " + std::to_string(tableCount) + " entries");
    }

    // Scan backward entries
    scanAddr = addr;
    Address prevAddr;
    try {
        prevAddr = addr.subtract(entryLen);
    } catch (...) {
        return;
    }
    int negCount = 0;
    while (negCount < MAX_NEG_ENTRIES) {
        if (listing->getInstructionContaining(prevAddr)) break;
        Address target = readTableEntry(prevAddr);
        if (!target.isValid()) break;

        symTable->createLabel(target, "switch_case_neg" + std::to_string(negCount),
                              SourceType::ANALYSIS);
        if (refInstr) {
            refMgr->addMemoryReference(refInstr->getAddress(), target,
                                       &RefTypes::DATA, SourceType::ANALYSIS, opIndex);
        }
        ++negCount;
        try {
            prevAddr = prevAddr.subtract(entryLen);
        } catch (...) {
            break;
        }
    }
}

} // namespace ghidra
