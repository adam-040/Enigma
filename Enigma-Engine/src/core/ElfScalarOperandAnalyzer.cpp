#include <ghidra/ElfScalarOperandAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Scalar.h>
#include <ghidra/AddressSpace.h>

namespace ghidra {

ElfScalarOperandAnalyzer::ElfScalarOperandAnalyzer()
    : ScalarOperandAnalyzer("ELF Scalar Operand References",
                            "Removes bad memory references created by scalar offsets relative to .got in zero-based ELF shared objects.") {
}

bool ElfScalarOperandAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "ELF";
}

bool ElfScalarOperandAnalyzer::getDefaultEnablement(Program* program) const {
    if (!program || program->getExecutableFormat() != "ELF") return false;
    return ScalarOperandAnalyzer::getDefaultEnablement(program);
}

bool ElfScalarOperandAnalyzer::addReference(Program* program, Instruction* instr,
                                             int opIndex, const AddressSpace* space,
                                             Scalar* scalar) {
    if (!program || !instr || !scalar) return false;
    if (program->getExecutableFormat() != "ELF") {
        return ScalarOperandAnalyzer::addReference(program, instr, opIndex, space, scalar);
    }

    std::string mnemonic = instr->getMnemonicString();
    auto* memory = program->getMemory();

    if (mnemonic == "add") {
        try {
            Address gotAddr = instr->getMinAddress().add(static_cast<int64_t>(scalar->getUnsignedValue()));
            MemoryBlock* block = memory->getBlock(gotAddr);
            if (block) {
                std::string blockName = block->getName();
                if (blockName.find(".got") != std::string::npos) {
                    return false;
                }
            }
        } catch (...) {
            // AddressOutOfBoundsException
        }
    } else if (mnemonic == "push") {
        MemoryBlock* block = memory->getBlock(instr->getMinAddress());
        if (block) {
            std::string blockName = block->getName();
            if (blockName.find(".plt") != std::string::npos) {
                return false;
            }
        }
    }

    return ScalarOperandAnalyzer::addReference(program, instr, opIndex, space, scalar);
}

} // namespace ghidra
