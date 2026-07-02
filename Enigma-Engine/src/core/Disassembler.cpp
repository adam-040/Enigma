/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Disassembler.cpp
/// \brief Disassembler adapter implementation using Capstone
#include "ghidra/Disassembler.h"
#include "ghidra/ProgramDB.h"
#include "ghidra/Listing.h"
#include "ghidra/Instruction.h"
#include "ghidra/Memory.h"
#include "ghidra/Msg.h"

#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <capstone/arm64.h>
#include <unordered_map>

namespace ghidra {

// Extract address-relevant scalar values from a Capstone instruction.
// For x86/x86_64 this resolves RIP/EIP-relative displacements to absolute
// addresses and records absolute immediates / absolute memory operands.
static void extractOperandScalars(const cs_insn* insn, DisassembledInstruction& di, int bitness) {
    if (!insn || !insn->detail) return;

    const cs_x86& x86 = insn->detail->x86;
    di.operandScalars.resize(x86.op_count);

    for (uint8_t i = 0; i < x86.op_count; ++i) {
        const cs_x86_op& op = x86.operands[i];
        std::vector<std::unique_ptr<Scalar>>& out = di.operandScalars[i];

        if (op.type == X86_OP_IMM) {
            // Immediate operands may be addresses (e.g. absolute CALL/JMP on x86,
            // or address constants loaded into registers).  Let ScalarOperandAnalyzer
            // decide whether the value is a valid address.
            int scalarBits = (bitness >= 64) ? 64 : 32;
            out.push_back(std::make_unique<Scalar>(scalarBits, op.imm));
        } else if (op.type == X86_OP_MEM) {
            bool hasBase = (op.mem.base != X86_REG_INVALID);
            bool hasIndex = (op.mem.index != X86_REG_INVALID);
            bool isRipRelative = (op.mem.base == X86_REG_RIP || op.mem.base == X86_REG_EIP);

            if (isRipRelative) {
                // RIP-relative: target = instruction_addr + instruction_len + disp
                uint64_t target = insn->address + insn->size + static_cast<uint64_t>(op.mem.disp);
                out.push_back(std::make_unique<Scalar>(64, static_cast<int64_t>(target)));
            } else if (!hasBase && !hasIndex && op.mem.disp != 0) {
                // Absolute memory operand such as [0xNNNN]
                int scalarBits = (bitness >= 64) ? 64 : 32;
                out.push_back(std::make_unique<Scalar>(scalarBits, static_cast<int64_t>(op.mem.disp)));
            }
            // [reg+disp] and [base+index*scale] displacements are offsets, not
            // addresses, so they are intentionally skipped to avoid false positives.
        }
    }
}

FlowType* Disassembler::determineFlowType(const std::string& mnemonic, const std::vector<std::string>& operands) {
    if (mnemonic == "jmp" || mnemonic == "b" || mnemonic == "br" || mnemonic == "jr" ||
        mnemonic == "bctr" || mnemonic == "b" ||
        (mnemonic == "jmpq" && !operands.empty() && operands[0].find('*') == 0)) {
        return const_cast<FlowType*>(&RefTypes::UNCONDITIONAL_JUMP);
    }
    if (mnemonic == "je" || mnemonic == "jne" || mnemonic == "jz" || mnemonic == "jnz" ||
        mnemonic == "beq" || mnemonic == "bne" ||
        mnemonic == "jg" || mnemonic == "jge" || mnemonic == "jl" || mnemonic == "jle" ||
        mnemonic == "ja" || mnemonic == "jae" || mnemonic == "jb" || mnemonic == "jbe" ||
        mnemonic == "jo" || mnemonic == "jno" || mnemonic == "js" || mnemonic == "jns" ||
        mnemonic == "jp" || mnemonic == "jnp" ||
        mnemonic == "jecxz" || mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "bgt" || mnemonic == "bge" || mnemonic == "blt" || mnemonic == "ble" ||
        mnemonic == "bhi" || mnemonic == "bhs" || mnemonic == "blo" || mnemonic == "bls" ||
        mnemonic == "bmi" || mnemonic == "bpl" || mnemonic == "bvc" || mnemonic == "bvs") {
        return const_cast<FlowType*>(&RefTypes::CONDITIONAL_JUMP);
    }
    if (mnemonic == "call" || mnemonic == "bl" || mnemonic == "blx" || mnemonic == "jal" ||
        mnemonic == "jalr" || mnemonic == "blr") {
        return const_cast<FlowType*>(&RefTypes::UNCONDITIONAL_CALL);
    }
    if (mnemonic == "ret" || mnemonic == "bx" || mnemonic == "syscall" || mnemonic == "svc" ||
        (mnemonic == "pop" && !operands.empty() && operands[0] == "pc")) {
        return const_cast<FlowType*>(&RefTypes::TERMINATOR);
    }
    return const_cast<FlowType*>(&RefTypes::FALL_THROUGH);
}

class CapstoneDisassembler : public Disassembler {
public:
    CapstoneDisassembler() : handle_(0), arch_("unknown"), alignment_(1), bitness_(64) {}

    ~CapstoneDisassembler() override {
        if (handle_ != 0) {
            cs_close(&handle_);
        }
    }

    bool initialize(const std::string& architecture, int bitness, bool bigEndian) override {
        cs_arch csArch;
        cs_mode csMode = CS_MODE_LITTLE_ENDIAN;

        if (bigEndian) csMode = CS_MODE_BIG_ENDIAN;

        if (architecture == "x86" || architecture == "i386") {
            csArch = CS_ARCH_X86;
            csMode = (bitness == 64) ? CS_MODE_64 : CS_MODE_32;
            alignment_ = 1;
            bitness_ = bitness;
        } else if (architecture.find("arm") != std::string::npos || architecture.find("ARM") != std::string::npos) {
            csArch = (bitness == 64) ? CS_ARCH_ARM64 : CS_ARCH_ARM;
            csMode = CS_MODE_ARM;
            alignment_ = 4;
            bitness_ = bitness;
        } else if (architecture.find("mips") != std::string::npos || architecture.find("MIPS") != std::string::npos) {
            csArch = CS_ARCH_MIPS;
            csMode = (bitness == 64) ? CS_MODE_MIPS64 : CS_MODE_MIPS32;
            alignment_ = 4;
            bitness_ = bitness;
        } else if (architecture.find("ppc") != std::string::npos || architecture.find("PowerPC") != std::string::npos) {
            csArch = CS_ARCH_PPC;
            csMode = (bitness == 64) ? CS_MODE_64 : CS_MODE_32;
            alignment_ = 4;
            bitness_ = bitness;
        } else {
            Msg::error("CapstoneDisassembler", "Unsupported architecture: " + architecture);
            return false;
        }

        if (cs_open(csArch, csMode, &handle_) != CS_ERR_OK) {
            Msg::error("CapstoneDisassembler", "Failed to initialize Capstone for " + architecture);
            return false;
        }

        cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
        arch_ = architecture;
        return true;
    }

    DisassembledInstruction disassembleOne(const std::vector<uint8_t>& bytes, uint64_t address) override {
        DisassembledInstruction result;
        result.address = Address();
        result.length = 0;
        result.flowType = const_cast<FlowType*>(&RefTypes::FALL_THROUGH);
        result.byteCount = 0;

        if (handle_ == 0 || bytes.empty()) return result;

        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle_, bytes.data(), bytes.size(), address, 1, &insn);

        if (count > 0 && insn) {
            result.mnemonic = insn->mnemonic;
            result.length = static_cast<int>(insn->size);
            result.byteCount = static_cast<int>(insn->size);
            for (int i = 0; i < result.byteCount && i < 16; ++i) {
                result.bytes[i] = insn->bytes[i];
            }

            result.address = Address(program_ ? program_->getAddressMap()->getDefaultAddressSpace() : nullptr, insn->address);

            if (insn->op_str[0] != '\0') {
                std::string ops = insn->op_str;
                size_t pos = 0;
                while ((pos = ops.find(',')) != std::string::npos) {
                    result.operands.push_back(ops.substr(0, pos));
                    ops.erase(0, pos + 1);
                }
                if (!ops.empty()) result.operands.push_back(ops);
            }

            result.flowType = determineFlowType(result.mnemonic, result.operands);
            extractOperandScalars(insn, result, bitness_);
            cs_free(insn, count);
        }

        return result;
    }

    std::vector<DisassembledInstruction> disassembleRange(
        const std::vector<uint8_t>& bytes,
        uint64_t startAddress,
        size_t maxSize,
        size_t maxInstructions) override
    {
        std::vector<DisassembledInstruction> results;
        if (handle_ == 0 || bytes.empty()) return results;

        size_t size = std::min(maxSize, bytes.size());
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle_, bytes.data(), size, startAddress, maxInstructions, &insn);

        AddressSpace* defaultSpace = program_ ? program_->getAddressMap()->getDefaultAddressSpace() : nullptr;

        for (size_t i = 0; i < count; ++i) {
            DisassembledInstruction di;
            di.address = Address(defaultSpace, insn[i].address);
            di.mnemonic = insn[i].mnemonic;
            di.length = static_cast<int>(insn[i].size);
            di.byteCount = static_cast<int>(insn[i].size);
            for (int j = 0; j < di.byteCount && j < 16; ++j) {
                di.bytes[j] = insn[i].bytes[j];
            }

            if (insn[i].op_str[0] != '\0') {
                std::string ops = insn[i].op_str;
                size_t pos = 0;
                while ((pos = ops.find(',')) != std::string::npos) {
                    di.operands.push_back(ops.substr(0, pos));
                    ops.erase(0, pos + 1);
                }
                if (!ops.empty()) di.operands.push_back(ops);
            }

            di.flowType = determineFlowType(di.mnemonic, di.operands);
            extractOperandScalars(&insn[i], di, bitness_);
            results.push_back(std::move(di));
        }

        if (insn) cs_free(insn, count);
        return results;
    }

    bool populateListing(ProgramDB* program, const Address& startAddr, const Address& endAddr) override {
        if (!program) return false;

        Memory* mem = program->getMemory();
        if (!mem) return false;

        Listing* listing = program->getListing();
        if (!listing) return false;

        uint64_t start = startAddr.getOffset();
        uint64_t end = endAddr.getOffset();
        size_t totalSize = static_cast<size_t>(end - start + 1);

        std::vector<uint8_t> bytes(totalSize);
        if (!mem->getBytes(startAddr, bytes.data(), static_cast<int>(totalSize))) {
            return false;
        }

        auto instructions = disassembleRange(bytes, start, totalSize, totalSize);

        for (auto& di : instructions) {
            auto* inst = new Instruction(program, di.address, di.mnemonic, di.length, di.flowType);
            for (const auto& op : di.operands) {
                inst->setOperand(static_cast<int>(inst->getNumOperands()), op);
            }
            for (size_t oi = 0; oi < di.operandScalars.size(); ++oi) {
                for (auto& scalar : di.operandScalars[oi]) {
                    if (scalar) {
                        inst->addOperandScalar(static_cast<int>(oi), scalar.release());
                    }
                }
            }
            listing->addInstruction(inst);
        }

        return true;
    }

    std::string getArchitecture() const override { return arch_; }
    int getInstructionAlignment() const override { return alignment_; }

private:
    csh handle_;
    std::string arch_;
    int alignment_;
    int bitness_;
};

void Disassembler::setProgram(ProgramDB* program) {
    program_ = program;
}

std::unique_ptr<Disassembler> createDisassembler(const std::string& architecture, int bitness, bool bigEndian) {
    auto disassembler = std::make_unique<CapstoneDisassembler>();
    if (!disassembler->initialize(architecture, bitness, bigEndian)) {
        return nullptr;
    }
    return disassembler;
}

} // namespace ghidra
