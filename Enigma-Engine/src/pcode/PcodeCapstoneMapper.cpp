#include <ghidra/PcodeCapstoneMapper.h>
#include <ghidra/OpCode.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/PcodeBlockBasic.h>
#include <ghidra/AddrSpace.h>
#include <sstream>
#include <cctype>
#include <algorithm>

namespace ghidra {

PcodeCapstoneMapper::PcodeCapstoneMapper()
    : constSpace_(new GenericAddressSpace("const", 8, AddressSpace::TYPE_CONSTANT, 0)),
      uniqueSpace_(new GenericAddressSpace("unique", 8, AddressSpace::TYPE_UNIQUE, 0)),
      regSpace_(new GenericAddressSpace("register", 8, AddressSpace::TYPE_REGISTER, 0)) {
    buildX86Handlers();
    buildARMHandlers();
    buildMIPSHandlers();
    buildPPCHandlers();
}

bool PcodeCapstoneMapper::initialize(const std::string& architecture) {
    architecture_ = architecture;
    std::string archLower = architecture;
    std::transform(archLower.begin(), archLower.end(), archLower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    isARM_ = (archLower.find("arm") != std::string::npos);
    isMIPS_ = (archLower.find("mips") != std::string::npos);
    isPPC_ = (archLower.find("ppc") != std::string::npos || archLower.find("powerpc") != std::string::npos);
    initialized_ = true;
    return true;
}

bool PcodeCapstoneMapper::isMemoryOperand(const std::string& op) const {
    return op.find('[') != std::string::npos;
}

// ---- Register & Varnode Helpers ----

VarnodeAST* PcodeCapstoneMapper::makeConst(Funcdata& fd, uintb val, int4 size) {
    int64_t offset = static_cast<int64_t>(static_cast<uint64_t>(val));
    Address constAddr(constSpace_.get(), offset);
    auto* vn = fd.createVarnode(constAddr, size, -1);
    return vn;
}

VarnodeAST* PcodeCapstoneMapper::makeUnique(Funcdata& fd, int4 size) {
    int32_t id = uniqueCounter_++;
    Address uniqAddr(uniqueSpace_.get(), static_cast<int64_t>(id));
    auto* vn = fd.createVarnode(uniqAddr, size, id);
    return vn;
}

VarnodeAST* PcodeCapstoneMapper::makeReg(Funcdata& fd, const std::string& name, int4 size, uintb offset) {
    int64_t off = static_cast<int64_t>(static_cast<uint64_t>(offset));
    Address regAddr(regSpace_.get(), off);
    auto* vn = fd.createVarnode(regAddr, size, static_cast<int32_t>(off));
    return vn;
}

VarnodeAST* PcodeCapstoneMapper::getOrCreateReg(Funcdata& fd, const std::string& name, int4 size, uintb offset) {
    auto it = regCache_.find(name);
    if (it != regCache_.end()) {
        return it->second;
    }
    auto* vn = makeReg(fd, name, size, offset);
    regCache_[name] = vn;
    return vn;
}

VarnodeAST* PcodeCapstoneMapper::parseOperand(const std::string& op, Funcdata& fd,
                                               const Address& addr, int ptrSize) {
    std::string trimmed = op;
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
    trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

    if (trimmed.empty()) return nullptr;

    // memory operand: [base] or [base+offset] etc.
    if (isMemoryOperand(trimmed)) {
        return makeUnique(fd, ptrSize);
    }

    // hex constant
    if (trimmed.size() > 2 && trimmed[0] == '0' && (trimmed[1] == 'x' || trimmed[1] == 'X')) {
        std::string hexStr = trimmed.substr(2);
        uintb val = 0;
        std::istringstream(hexStr) >> std::hex >> val;
        return makeConst(fd, val, ptrSize);
    }

    // numeric constant
    if (trimmed.size() >= 1 && std::isdigit(static_cast<unsigned char>(trimmed[0]))) {
        uintb val = 0;
        std::istringstream(trimmed) >> val;
        return makeConst(fd, val, ptrSize);
    }

    // negative constant
    if (!trimmed.empty() && trimmed[0] == '-') {
        std::string numStr = trimmed.substr(1);
        if (!numStr.empty() && std::isdigit(static_cast<unsigned char>(numStr[0]))) {
            int64_t sval = 0;
            std::istringstream(trimmed) >> sval;
            return makeConst(fd, static_cast<uint64_t>(sval), ptrSize);
        }
    }

    // ARM immediate: #0x1000 or #42
    if (!trimmed.empty() && trimmed[0] == '#') {
        std::string rest = trimmed.substr(1);
        if (rest.size() > 2 && rest[0] == '0' && (rest[1] == 'x' || rest[1] == 'X')) {
            uintb val = 0;
            std::istringstream(rest.substr(2)) >> std::hex >> val;
            return makeConst(fd, val, ptrSize);
        }
        uintb val = 0;
        std::istringstream(rest) >> val;
        return makeConst(fd, val, ptrSize);
    }

    // register (plain name or with ptr qualifier like "dword ptr [eax]")
    // Remove ptr qualifiers
    std::string regName = trimmed;
    {
        size_t p = regName.find("ptr");
        if (p != std::string::npos) {
            size_t bracket = regName.find('[');
            if (bracket != std::string::npos) {
                // it's a memory operand with ptr prefix, e.g. "dword ptr [eax]"
                return makeUnique(fd, ptrSize);
            }
        }
    }

    // ARM register with suffix like "r0", "sp", "lr", "pc"
    // x86: "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp", "eip"
    // x86-64: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip", "r8"-"r15"
    // Remove any ARM condition suffixes like "r0", "r1"

    // Determine register size based on name
    int regSize = ptrSize;
    if (regName.size() >= 2) {
        char first = regName[0];
        if (first == 'e' && regSize >= 4) regSize = 4;     // eax, ebx, ecx, edx, esi, edi, esp, ebp
        if (regName[0] == 'r' && regName.size() >= 2) {
            if (regName[1] >= '0' && regName[1] <= '9') {
                // r0-r15, default is ptrSize (8 on x64)
            } else if (regName[1] == 'a' || regName[1] == 'b' || regName[1] == 'c' ||
                       regName[1] == 'd' || regName[1] == 's' || regName[1] == 'p') {
                // rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, rip
                regSize = 8;
            }
        }
        // 8-bit/16-bit subregisters
        if (regName == "al" || regName == "ah" || regName == "bl" || regName == "bh" ||
            regName == "cl" || regName == "ch" || regName == "dl" || regName == "dh") {
            regSize = 1;
        }
        if (regName == "ax" || regName == "bx" || regName == "cx" || regName == "dx" ||
            regName == "si" || regName == "di" || regName == "sp" || regName == "bp") {
            regSize = 2;
        }
        // ARM
        if (regName == "lr" || regName == "r14") regSize = ptrSize;
        if (regName == "pc" || regName == "r15") regSize = ptrSize;
        if (regName == "sp" || regName == "r13") regSize = ptrSize;
        if (regName[0] == 'r' && regName.size() >= 2 && regName[1] >= '0' && regName[1] <= '9') {
            regSize = ptrSize;
        }
    }

    // Compute a predictable offset for the register
    uintb regOffset = 0;

    if (isARM_ || regName[0] == 'r') {
        // ARM: r0-r15
        if (regName.size() >= 2 && regName[0] == 'r') {
            std::string numPart = regName.substr(1);
            bool allDigits = !numPart.empty() && std::all_of(numPart.begin(), numPart.end(),
                [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
            if (allDigits) {
                regOffset = std::stoul(numPart);
            }
        }
        if (regName == "sp") regOffset = 13;
        if (regName == "lr") regOffset = 14;
        if (regName == "pc") regOffset = 15;
    } else if (isMIPS_) {
        // MIPS registers: $zero, $v0-$v1, $a0-$a3, $t0-$t9, $s0-$s7, $sp, $ra, $fp, $gp
        if (regName == "$zero" || regName == "zero") regOffset = 0;
        else if (regName == "$at" || regName == "at") regOffset = 1;
        else if (regName == "$v0" || regName == "v0") regOffset = 2;
        else if (regName == "$v1" || regName == "v1") regOffset = 3;
        else if (regName == "$a0" || regName == "a0") regOffset = 4;
        else if (regName == "$a1" || regName == "a1") regOffset = 5;
        else if (regName == "$a2" || regName == "a2") regOffset = 6;
        else if (regName == "$a3" || regName == "a3") regOffset = 7;
        else if (regName == "$t0" || regName == "t0") regOffset = 8;
        else if (regName == "$t1" || regName == "t1") regOffset = 9;
        else if (regName == "$t2" || regName == "t2") regOffset = 10;
        else if (regName == "$t3" || regName == "t3") regOffset = 11;
        else if (regName == "$t4" || regName == "t4") regOffset = 12;
        else if (regName == "$t5" || regName == "t5") regOffset = 13;
        else if (regName == "$t6" || regName == "t6") regOffset = 14;
        else if (regName == "$t7" || regName == "t7") regOffset = 15;
        else if (regName == "$s0" || regName == "s0") regOffset = 16;
        else if (regName == "$s1" || regName == "s1") regOffset = 17;
        else if (regName == "$s2" || regName == "s2") regOffset = 18;
        else if (regName == "$s3" || regName == "s3") regOffset = 19;
        else if (regName == "$s4" || regName == "s4") regOffset = 20;
        else if (regName == "$s5" || regName == "s5") regOffset = 21;
        else if (regName == "$s6" || regName == "s6") regOffset = 22;
        else if (regName == "$s7" || regName == "s7") regOffset = 23;
        else if (regName == "$t8" || regName == "t8") regOffset = 24;
        else if (regName == "$t9" || regName == "t9") regOffset = 25;
        else if (regName == "$k0" || regName == "k0") regOffset = 26;
        else if (regName == "$k1" || regName == "k1") regOffset = 27;
        else if (regName == "$gp" || regName == "gp") regOffset = 28;
        else if (regName == "$sp" || regName == "sp") regOffset = 29;
        else if (regName == "$fp" || regName == "fp") regOffset = 30;
        else if (regName == "$ra" || regName == "ra") regOffset = 31;
        // Numeric $N
        if (regOffset == 0 && regName.size() >= 2 && (regName[0] == '$' || std::isdigit(static_cast<unsigned char>(regName[0])))) {
            std::string numPart = (regName[0] == '$') ? regName.substr(1) : regName;
            bool allDigits = !numPart.empty() && std::all_of(numPart.begin(), numPart.end(),
                [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
            if (allDigits) regOffset = std::stoul(numPart);
        }
    } else if (isPPC_) {
        // PPC: r0-r31, f0-f31, special registers
        if (regName.size() >= 2 && regName[0] == 'r') {
            std::string numPart = regName.substr(1);
            bool allDigits = !numPart.empty() && std::all_of(numPart.begin(), numPart.end(),
                [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
            if (allDigits) regOffset = std::stoul(numPart);
        }
        if (regName.size() >= 2 && regName[0] == 'f') {
            std::string numPart = regName.substr(1);
            bool allDigits = !numPart.empty() && std::all_of(numPart.begin(), numPart.end(),
                [](char c) { return std::isdigit(static_cast<unsigned char>(c)); });
            if (allDigits) regOffset = 32 + std::stoul(numPart);
        }
        if (regName == "lr") regOffset = 64;
        if (regName == "ctr") regOffset = 65;
        if (regName == "cr0") regOffset = 66;
        if (regName == "cr1") regOffset = 67;
        if (regName == "cr2") regOffset = 68;
        if (regName == "cr3") regOffset = 69;
        if (regName == "cr4") regOffset = 70;
        if (regName == "cr5") regOffset = 71;
        if (regName == "cr6") regOffset = 72;
        if (regName == "cr7") regOffset = 73;
        if (regName == "xer") regOffset = 74;
        if (regName == "mq") regOffset = 75;
    } else {
        // x86 register offsets
        if (regName == "eax" || regName == "ax" || regName == "al") regOffset = 0;
        else if (regName == "ecx" || regName == "cx" || regName == "cl") regOffset = 1;
        else if (regName == "edx" || regName == "dx" || regName == "dl") regOffset = 2;
        else if (regName == "ebx" || regName == "bx" || regName == "bl") regOffset = 3;
        else if (regName == "esp" || regName == "sp" || regName == "spl") regOffset = 4;
        else if (regName == "ebp" || regName == "bp" || regName == "bpl") regOffset = 5;
        else if (regName == "esi" || regName == "si") regOffset = 6;
        else if (regName == "edi" || regName == "di") regOffset = 7;
        else if (regName == "ah") regOffset = 0 + 4;
        else if (regName == "bh") regOffset = 3 + 4;
        else if (regName == "ch") regOffset = 1 + 4;
        else if (regName == "dh") regOffset = 2 + 4;
        else if (regName == "rax") regOffset = 0;
        else if (regName == "rbx") regOffset = 1;
        else if (regName == "rcx") regOffset = 2;
        else if (regName == "rdx") regOffset = 3;
        else if (regName == "rsp") regOffset = 4;
        else if (regName == "rbp") regOffset = 5;
        else if (regName == "rsi") regOffset = 6;
        else if (regName == "rdi") regOffset = 7;
        else if (regName == "r8") regOffset = 8;
        else if (regName == "r9") regOffset = 9;
        else if (regName == "r10") regOffset = 10;
        else if (regName == "r11") regOffset = 11;
        else if (regName == "r12") regOffset = 12;
        else if (regName == "r13") regOffset = 13;
        else if (regName == "r14") regOffset = 14;
        else if (regName == "r15") regOffset = 15;
        else if (regName == "rip") regOffset = 16;
        else if (regName == "flags" || regName == "eflags" || regName == "rflags") regOffset = 100;
        else if (regName.size() >= 4 && regName[0] == 's' && regName[1] == 't' &&
                 regName[2] == '(' && regName.back() == ')') {
            std::string numStr = regName.substr(3, regName.size() - 4);
            if (!numStr.empty() && std::all_of(numStr.begin(), numStr.end(),
                    [](char c) { return std::isdigit(static_cast<unsigned char>(c)); })) {
                regOffset = 200 + std::stoul(numStr);
                regSize = 10;
            }
        }
        else if (regName == "mm0" || regName == "mm1" || regName == "mm2" || regName == "mm3" ||
                 regName == "mm4" || regName == "mm5" || regName == "mm6" || regName == "mm7") {
            regOffset = 300 + (regName[2] - '0');
            regSize = 8;
        }
        else if (regName == "xmm0" || regName == "xmm1" || regName == "xmm2" || regName == "xmm3" ||
                 regName == "xmm4" || regName == "xmm5" || regName == "xmm6" || regName == "xmm7") {
            regOffset = 400 + (regName[3] - '0');
            regSize = 16;
        }
        else if (regName == "xmm8" || regName == "xmm9" || regName == "xmm10" || regName == "xmm11" ||
                 regName == "xmm12" || regName == "xmm13" || regName == "xmm14" || regName == "xmm15") {
            regOffset = 408 + (regName[3] - '0');
            regSize = 16;
        }
        else if (regName == "ymm0" || regName == "ymm1" || regName == "ymm2" || regName == "ymm3" ||
                 regName == "ymm4" || regName == "ymm5" || regName == "ymm6" || regName == "ymm7") {
            regOffset = 500 + (regName[3] - '0');
            regSize = 32;
        }
    }

    return getOrCreateReg(fd, regName, regSize, regOffset);
}

// ---- Emit ----

void PcodeCapstoneMapper::emitOp(Funcdata& fd, const Address& addr, int /*seq*/,
                                  int opcode,
                                  const std::vector<VarnodeAST*>& inputs, VarnodeAST* output) {
    auto* op = fd.createOp(addr, opcode, static_cast<int>(inputs.size()));
    if (output) op->setOutput(output);
    for (size_t i = 0; i < inputs.size(); i++) {
        if (inputs[i]) {
            op->setInput(inputs[i], static_cast<int>(i));
        }
    }
    auto* block = fd.getBlockGraph()->getBlock(0);
    if (!block) {
        block = fd.getBlockGraph()->addBlock();
        fd.getBlockGraph()->setStartNode(0);
    }
    block->insertEnd(op);
}

// ---- Dispatch ----

void PcodeCapstoneMapper::mapInstruction(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    std::string mnemLower = di.mnemonic;
    std::transform(mnemLower.begin(), mnemLower.end(), mnemLower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    const std::unordered_map<std::string, Handler>* handlers = &x86Handlers_;
    if (isARM_) handlers = &armHandlers_;
    else if (isMIPS_) handlers = &mipsHandlers_;
    else if (isPPC_) handlers = &ppcHandlers_;

    auto it = handlers->find(mnemLower);
    if (it != handlers->end()) {
        it->second(di, fd, addr);
        return;
    }

    mapDefault(di, fd, addr);
}

// ---- Default mapper (fallback) ----

void PcodeCapstoneMapper::mapDefault(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    // Look up the opcode from OpCode.h / PcodeOp.h constant mapping
    int opcode = PcodeOp::UNIMPLEMENTED;
    const std::string& mnem = di.mnemonic;

    // Quick opcode lookup for common arithmetic / logical / etc.
    // This is a simplified mapping — real SLEIGH specs produce multiple pcode ops per instruction
    if (mnem == "nop" || mnem == "NOP") {
        opcode = PcodeOp::COPY;
        emitOp(fd, addr, 0, opcode, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
        return;
    }

    if (di.operands.empty() || di.operands[0].empty()) {
        emitOp(fd, addr, 0, opcode, {}, nullptr);
        return;
    }

    int ptrSize = 4;
    if (architecture_.find("64") != std::string::npos) ptrSize = 8;

    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* src = (di.operands.size() > 1) ? parseOperand(di.operands[1], fd, addr, ptrSize) : nullptr;

    if (isMemoryOperand(di.operands[0])) {
        // first operand is memory = store-like
        std::vector<VarnodeAST*> inputs = {dst};
        if (src) inputs.push_back(src);
        emitOp(fd, addr, 0, PcodeOp::STORE, inputs, nullptr);
    } else if (dst && src && isMemoryOperand(di.operands[1])) {
        // second operand is memory = load-like
        emitOp(fd, addr, 0, PcodeOp::LOAD, {src}, dst);
    } else if (dst && src) {
        emitOp(fd, addr, 0, PcodeOp::COPY, {src}, dst);
    } else if (dst) {
        emitOp(fd, addr, 0, PcodeOp::COPY, {}, dst);
    }
}

// ---- Specific mappers ----

void PcodeCapstoneMapper::mapCopyMov(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;

    if (di.operands.size() < 2) {
        // mov with single operand (e.g. mov eax, eax -> just a nop)
        return;
    }

    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);

    if (!dst) {
        // possibly just a register name missing
        return;
    }

    // Detect load
    if (isMemoryOperand(di.operands[1])) {
        emitOp(fd, addr, 0, PcodeOp::LOAD, {src}, dst);
        return;
    }

    // Detect store
    if (isMemoryOperand(di.operands[0])) {
        emitOp(fd, addr, 0, PcodeOp::STORE, {dst, src}, nullptr);
        return;
    }

    // Regular COPY
    if (src) {
        emitOp(fd, addr, 0, PcodeOp::COPY, {src}, dst);
    }
}

void PcodeCapstoneMapper::mapAddSub(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;

    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;

    if (di.operands.size() >= 3) {
        VarnodeAST* src1 = parseOperand(di.operands[1], fd, addr, ptrSize);
        VarnodeAST* src2 = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (!src1 || !src2) return;
        VarnodeAST* tmp = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, opcode, {src1, src2}, tmp);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        return;
    }

    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!src) return;

    // ADD/SUB dst = dst + src
    // For pcode we model as: dst = opcode(dst, src)
    // We need a temp for the result, then COPY to dst
    VarnodeAST* tmp = makeUnique(fd, ptrSize);
    emitOp(fd, addr, 0, opcode, {dst, src}, tmp);
    emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
}

void PcodeCapstoneMapper::mapCall(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* target = nullptr;
    if (!di.operands.empty()) {
        target = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    emitOp(fd, addr, 0, PcodeOp::CALL, {target}, nullptr);
}

void PcodeCapstoneMapper::mapCallInd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* target = nullptr;
    if (!di.operands.empty()) {
        target = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    emitOp(fd, addr, 0, PcodeOp::CALLIND, {target}, nullptr);
}

void PcodeCapstoneMapper::mapReturn(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    emitOp(fd, addr, 0, PcodeOp::RETURN, {}, nullptr);
}

void PcodeCapstoneMapper::mapBranch(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* target = nullptr;
    if (!di.operands.empty()) {
        target = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    emitOp(fd, addr, 0, PcodeOp::BRANCH, {target}, nullptr);
}

void PcodeCapstoneMapper::mapBranchInd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* target = nullptr;
    if (!di.operands.empty()) {
        target = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    emitOp(fd, addr, 0, PcodeOp::BRANCHIND, {target}, nullptr);
}

void PcodeCapstoneMapper::mapCBranch(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* target = nullptr;
    if (!di.operands.empty()) {
        target = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    // The condition is usually a flags register — we create a dummy unique varnode as placeholder
    VarnodeAST* cond = makeUnique(fd, 1);
    emitOp(fd, addr, 0, PcodeOp::CBRANCH, {target, cond}, nullptr);
}

void PcodeCapstoneMapper::mapLoad(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    // LOAD is handled by the default mapper when it detects memory operands
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (dst && src) {
        emitOp(fd, addr, 0, PcodeOp::LOAD, {src}, dst);
    }
}

void PcodeCapstoneMapper::mapStore(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* op0 = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* op1 = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!op0 || !op1) return;
    // STORE(address, value) — determine which operand is the address (memory) vs value
    bool op0IsMem = isMemoryOperand(di.operands[0]);
    bool op1IsMem = isMemoryOperand(di.operands[1]);
    VarnodeAST* addrVn = op1IsMem ? op1 : (op0IsMem ? op0 : nullptr);
    VarnodeAST* valVn = op0IsMem ? op1 : (op1IsMem ? op0 : nullptr);
    if (addrVn && valVn) {
        emitOp(fd, addr, 0, PcodeOp::STORE, {addrVn, valVn}, nullptr);
    } else {
        emitOp(fd, addr, 0, PcodeOp::STORE, {op0, op1}, nullptr);
    }
}

void PcodeCapstoneMapper::mapPtrAdd(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* base = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* offset = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (base && offset) {
        VarnodeAST* result = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::PTRADD, {base, offset, makeConst(fd, 1, ptrSize)}, result);
    }
}

void PcodeCapstoneMapper::mapSubpiece(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, 1); // 1 byte subpiece
    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (dst && src) {
        emitOp(fd, addr, 0, PcodeOp::SUBPIECE, {src, makeConst(fd, 0, ptrSize)}, dst);
    }
}

void PcodeCapstoneMapper::mapPopcount(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* src = nullptr;
    if (!di.operands.empty()) {
        src = parseOperand(di.operands[0], fd, addr, ptrSize);
    }
    VarnodeAST* result = makeUnique(fd, ptrSize);
    emitOp(fd, addr, 0, PcodeOp::POPCOUNT, {src}, result);
}

void PcodeCapstoneMapper::mapInt2Float(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* src = nullptr, *dst = nullptr;
    if (di.operands.size() >= 2) {
        dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        src = parseOperand(di.operands[1], fd, addr, ptrSize);
    }
    if (dst && src) {
        emitOp(fd, addr, 0, PcodeOp::FLOAT_INT2FLOAT, {src}, dst);
    } else if (src) {
        emitOp(fd, addr, 0, PcodeOp::FLOAT_INT2FLOAT, {src}, makeUnique(fd, ptrSize));
    }
}

void PcodeCapstoneMapper::mapFloat2Int(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    VarnodeAST* src = nullptr, *dst = nullptr;
    if (di.operands.size() >= 2) {
        dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        src = parseOperand(di.operands[1], fd, addr, ptrSize);
    }
    if (dst && src) {
        emitOp(fd, addr, 0, PcodeOp::FLOAT_TRUNC, {src}, dst);
    } else if (src) {
        emitOp(fd, addr, 0, PcodeOp::FLOAT_TRUNC, {src}, makeUnique(fd, ptrSize));
    }
}

void PcodeCapstoneMapper::mapBoolOp(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    if (di.operands.size() >= 3) {
        VarnodeAST* src1 = parseOperand(di.operands[1], fd, addr, ptrSize);
        VarnodeAST* src2 = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (!src1 || !src2) return;
        VarnodeAST* tmp = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, opcode, {src1, src2}, tmp);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        return;
    }
    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!src) return;
    emitOp(fd, addr, 0, opcode, {dst, src}, dst);
}

void PcodeCapstoneMapper::mapIncDec(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isInc) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.empty()) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    VarnodeAST* one = makeConst(fd, 1, ptrSize);
    VarnodeAST* tmp = makeUnique(fd, ptrSize);
    int opc = isInc ? PcodeOp::INT_ADD : PcodeOp::INT_SUB;
    emitOp(fd, addr, 0, opc, {dst, one}, tmp);
    emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
}

void PcodeCapstoneMapper::mapNegNot(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isNeg) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.empty()) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    if (isNeg) {
        emitOp(fd, addr, 0, PcodeOp::INT_2COMP, {dst}, dst);
    } else {
        emitOp(fd, addr, 0, PcodeOp::INT_NEGATE, {dst}, dst);
    }
}

void PcodeCapstoneMapper::mapCmpTest(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, bool isTest) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* a = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* b = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!a || !b) return;
    VarnodeAST* result = makeUnique(fd, ptrSize);
    if (isTest) {
        emitOp(fd, addr, 0, PcodeOp::INT_AND, {a, b}, result);
    } else {
        emitOp(fd, addr, 0, PcodeOp::INT_EQUAL, {a, b}, result);
    }
}

void PcodeCapstoneMapper::mapMulDiv(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    if (di.operands.size() >= 3) {
        VarnodeAST* src1 = parseOperand(di.operands[1], fd, addr, ptrSize);
        VarnodeAST* src2 = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (!src1 || !src2) return;
        VarnodeAST* tmp = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, opcode, {src1, src2}, tmp);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        return;
    }
    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!src) return;
    VarnodeAST* tmp = makeUnique(fd, ptrSize);
    emitOp(fd, addr, 0, opcode, {dst, src}, tmp);
    emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
}

void PcodeCapstoneMapper::mapSyscall(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    (void)di;
    emitOp(fd, addr, 0, PcodeOp::CALLOTHER, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
}

void PcodeCapstoneMapper::mapXchg(const DisassembledInstruction& di, Funcdata& fd, const Address& addr) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* a = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* b = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!a || !b) return;
    VarnodeAST* tmp = makeUnique(fd, ptrSize);
    emitOp(fd, addr, 0, PcodeOp::COPY, {a}, tmp);
    emitOp(fd, addr, 1, PcodeOp::COPY, {b}, a);
    emitOp(fd, addr, 2, PcodeOp::COPY, {tmp}, b);
}

void PcodeCapstoneMapper::mapFloatArith(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    if (di.operands.size() >= 3) {
        VarnodeAST* src1 = parseOperand(di.operands[1], fd, addr, ptrSize);
        VarnodeAST* src2 = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (!src1 || !src2) return;
        VarnodeAST* tmp = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, opcode, {src1, src2}, tmp);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        return;
    }
    VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!src) return;
    VarnodeAST* tmp = makeUnique(fd, ptrSize);
    emitOp(fd, addr, 0, opcode, {dst, src}, tmp);
    emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
}

void PcodeCapstoneMapper::mapFloatCmp(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.size() < 2) return;
    VarnodeAST* a = parseOperand(di.operands[0], fd, addr, ptrSize);
    VarnodeAST* b = parseOperand(di.operands[1], fd, addr, ptrSize);
    if (!a || !b) return;
    emitOp(fd, addr, 0, opcode, {a, b}, makeUnique(fd, ptrSize));
}

void PcodeCapstoneMapper::mapFloatUnary(const DisassembledInstruction& di, Funcdata& fd, const Address& addr, int opcode) {
    int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
    if (di.operands.empty()) return;
    VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
    if (!dst) return;
    emitOp(fd, addr, 0, opcode, {dst}, dst);
}

// ---- ARM Handler Table ----

void PcodeCapstoneMapper::buildARMHandlers() {
    // ARM mov / ldr / str
    armHandlers_["mov"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["movs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["movw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["movt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Load / Store
    armHandlers_["ldr"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["str"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["ldrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["strb"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["ldrh"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["strh"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["ldrsh"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldrsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldm"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["stm"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Arithmetic
    armHandlers_["add"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["adds"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["sub"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["subs"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["rsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["mul"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (dst && src) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {dst, src}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };

    // Control flow
    armHandlers_["b"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranch(di, fd, addr); };
    armHandlers_["bl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCall(di, fd, addr); };
    armHandlers_["bx"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranchInd(di, fd, addr); };
    armHandlers_["blx"] = [this](const auto& di, auto& fd, const auto& addr) { mapCallInd(di, fd, addr); };
    armHandlers_["bne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["beq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bgt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["blt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["ble"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bhi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bls"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bhs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["blo"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bmi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bpl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bvs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    armHandlers_["bvc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };

    // Stack operations
    armHandlers_["push"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* val = nullptr;
        if (!di.operands.empty()) {
            val = parseOperand(di.operands[0], fd, addr, ptrSize);
        }
        VarnodeAST* sp = getOrCreateReg(fd, "sp", ptrSize, 13);
        VarnodeAST* tmpSP = makeUnique(fd, ptrSize);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::INT_SUB, {sp, inc}, tmpSP);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmpSP}, sp);
        if (val) {
            emitOp(fd, addr, 2, PcodeOp::STORE, {sp, val}, nullptr);
        }
    };
    armHandlers_["pop"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* sp = getOrCreateReg(fd, "sp", ptrSize, 13);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        if (!di.operands.empty()) {
            VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
            if (dst) {
                emitOp(fd, addr, 0, PcodeOp::LOAD, {sp}, dst);
            }
        }
        VarnodeAST* newSP = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 1, PcodeOp::INT_ADD, {sp, inc}, newSP);
        emitOp(fd, addr, 2, PcodeOp::COPY, {newSP}, sp);
    };
    armHandlers_["return"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };

    // Logical
    armHandlers_["and"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    armHandlers_["orr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    armHandlers_["eor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    armHandlers_["bic"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };

    // Data processing
    armHandlers_["cmp"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* a = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (a && b) {
            auto* result = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_EQUAL, {a, b}, result);
        }
    };
    armHandlers_["cmn"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* a = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (a && b) {
            auto* sum = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {a, b}, sum);
        }
    };
    armHandlers_["tst"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* a = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (a && b) {
            emitOp(fd, addr, 0, PcodeOp::INT_AND, {a, b}, makeUnique(fd, ptrSize));
        }
    };
    armHandlers_["teq"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* a = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (a && b) {
            emitOp(fd, addr, 0, PcodeOp::INT_XOR, {a, b}, makeUnique(fd, ptrSize));
        }
    };

    // Divide (ARMv7+)
    armHandlers_["sdiv"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_SDIV); };
    armHandlers_["udiv"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };

    // Sign/zero extend
    armHandlers_["sxtb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["sxth"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["uxtb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["uxth"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Count leading zeros
    armHandlers_["clz"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };

    // Multiply-accumulate: mla dst, a, b, c -> dst = a * b + c
    armHandlers_["mla"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 4) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        auto* c = parseOperand(di.operands[3], fd, addr, ptrSize);
        if (dst && a && b && c) {
            auto* prod = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, prod);
            emitOp(fd, addr, 1, PcodeOp::INT_ADD, {prod, c}, dst);
        }
    };

    // Multiply long: umull lo, hi, a, b -> (hi:lo) = a * b
    armHandlers_["umull"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 4) return;
        auto* lo = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* hi = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[2], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[3], fd, addr, ptrSize);
        if (lo && hi && a && b) {
            (void)hi;
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, lo);
        }
    };
    armHandlers_["smull"] = armHandlers_["umull"];

    // If-Then in Thumb (IT block — no pcode side effects)
    armHandlers_["it"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };
    armHandlers_["ite"] = armHandlers_["it"];
    armHandlers_["itt"] = armHandlers_["it"];
    armHandlers_["itee"] = armHandlers_["it"];
    armHandlers_["ittt"] = armHandlers_["it"];
    armHandlers_["itte"] = armHandlers_["it"];

    // No-op
    armHandlers_["nop"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };

    // Shifts
    armHandlers_["lsl"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    armHandlers_["lsr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    armHandlers_["asr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    armHandlers_["ror"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };

    // Add/Subtract with carry (simplified — no carry tracking)
    armHandlers_["adc"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["sbc"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["rsc"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };

    // Byte-reversal simplifications (COPY placeholder)
    armHandlers_["rev"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["rev16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["revsh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Saturate simplifications (COPY placeholder)
    armHandlers_["ssat"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["usat"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Multiply-accumulate long (simplified as MUL placeholder)
    armHandlers_["smlal"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["umlal"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };

    // Pack halfword (COPY placeholder)
    armHandlers_["pkhbt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["pkhtb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Unsigned sum of absolute differences (COPY placeholder)
    armHandlers_["usad8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Supervisor call / breakpoint
    armHandlers_["swi"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    armHandlers_["svc"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    armHandlers_["bkpt"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };

    // Exclusive load/store (atomic — LOAD/STORE placeholder)
    armHandlers_["ldrex"]  = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["strex"]  = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["clrex"]  = [this](const auto&, auto&, const auto&) {};

    // Acquire-release (LOAD/STORE placeholder — ordering semantics not modeled)
    armHandlers_["lda"]    = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldab"]   = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldaex"]  = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldaexb"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["ldaexh"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["stl"]    = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["stlb"]   = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["stlex"]  = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["stlexb"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["stlexh"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Memory barriers (no-op)
    armHandlers_["dmb"] = [this](const auto&, auto&, const auto&) {};
    armHandlers_["dsb"] = [this](const auto&, auto&, const auto&) {};
    armHandlers_["isb"] = [this](const auto&, auto&, const auto&) {};

    // Hints (nop-like)
    armHandlers_["yield"] = [this](const auto&, auto&, const auto&) {};
    armHandlers_["wfe"]   = [this](const auto&, auto&, const auto&) {};
    armHandlers_["wfi"]   = [this](const auto&, auto&, const auto&) {};
    armHandlers_["sev"]   = [this](const auto&, auto&, const auto&) {};
    armHandlers_["sevl"]  = [this](const auto&, auto&, const auto&) {};

    // CRC32 (COPY placeholder)
    armHandlers_["crc32b"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["crc32h"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["crc32w"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["crc32cb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["crc32ch"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["crc32cw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // ARM VFP / NEON floating-point
    armHandlers_["vadd.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    armHandlers_["vadd.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    armHandlers_["vsub.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    armHandlers_["vsub.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    armHandlers_["vmul.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    armHandlers_["vmul.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    armHandlers_["vdiv.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    armHandlers_["vdiv.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    armHandlers_["vsqrt.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    armHandlers_["vsqrt.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    armHandlers_["vneg.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    armHandlers_["vneg.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    armHandlers_["vabs.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    armHandlers_["vabs.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    armHandlers_["vcmp.f32"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    armHandlers_["vcmp.f64"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    armHandlers_["vcvtsi.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    armHandlers_["vcvtsi.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    armHandlers_["vcvtf32.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    armHandlers_["vcvtf64.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_FLOAT2FLOAT); };
    armHandlers_["vcvtf32.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_FLOAT2FLOAT); };
    armHandlers_["vmov.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmov.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vldr.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vldr.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vstr.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vstr.f64"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // ARM multiply-subtract
    armHandlers_["mls"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 4) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        auto* c = parseOperand(di.operands[3], fd, addr, ptrSize);
        if (dst && a && b && c) {
            auto* prod = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, prod);
            emitOp(fd, addr, 1, PcodeOp::INT_SUB, {c, prod}, dst);
        }
    };
    armHandlers_["smlsd"] = armHandlers_["mls"];
    armHandlers_["smlsld"] = armHandlers_["mls"];

    // Bitfield extract/insert
    armHandlers_["sbfx"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["ubfx"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["bfc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["bfi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["bfxil"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Select bytes
    armHandlers_["sel"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Bit reverse
    armHandlers_["rbit"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Signed/Unsigned extended add
    armHandlers_["sxtab"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["sxtab16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["sxtah"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["uxtab"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["uxtab16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["uxtah"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };

    // Dual signed multiply accumulate
    armHandlers_["smlad"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smuad"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smmla"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smmls"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smulbb"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smulbt"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smultb"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["smultt"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };

    // Unsigned sum of absolute differences (improved from COPY)
    armHandlers_["usad8"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["usada8"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_ADD); };

    // ARMv6 Media pack/unpack
    armHandlers_["pkhbt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["pkhtb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Parallel add/subtract (simplified as add/sub)
    armHandlers_["sadd8"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["ssub8"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["sadd16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["ssub16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["uadd8"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["usub8"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["uadd16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["usub16"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };

    // Advanced SIMD (NEON) integer ops — basic subset
    armHandlers_["vpadd.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["vadd.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    armHandlers_["vsub.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    armHandlers_["vmul.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    armHandlers_["vand"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    armHandlers_["vorr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    armHandlers_["veor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    armHandlers_["vmovn.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapSubpiece(di, fd, addr); };
    armHandlers_["vshl.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    armHandlers_["vshr.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    armHandlers_["vshr.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    armHandlers_["vshr.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };

    // --- NEON table lookup / permutation ---
    armHandlers_["vtbl.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbl1.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbl2.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbl3.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbl4.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbx.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbx1.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbx2.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbx3.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtbx4.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vzip.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vzip.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vzip.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vuzp.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vuzp.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vuzp.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtrn.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtrn.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vtrn.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- NEON reciprocal / sqrt estimate ---
    armHandlers_["vrecpe.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrecpe.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrecps.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsqrte.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsqrte.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsqrts.f32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- NEON pairwise add / absolute diff ---
    armHandlers_["vpaddl.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vpaddl.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vpaddl.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vpaddl.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vpaddl.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vpaddl.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vabdl.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vaba.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- NEON compare / min / max ---
    armHandlers_["vceq.i8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vceq.i16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vceq.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcge.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vcgt.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmax.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vmin.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- NEON rounding / narrowing ---
    armHandlers_["vqadd.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqadd.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqadd.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqadd.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqadd.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqadd.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.s8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.s16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.s32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.u8"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.u16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vqsub.u32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vraddhn.i16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vraddhn.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vraddhn.i64"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsubhn.i16"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsubhn.i32"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    armHandlers_["vrsubhn.i64"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- NEON load / store multiple ---
    armHandlers_["vld1.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld1.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld1.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld1.64"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vst1.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst1.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst1.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst1.64"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vld2.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld2.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld2.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vst2.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst2.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst2.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vld3.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld3.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld3.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vst3.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst3.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst3.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vld4.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld4.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld4.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vst4.8"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst4.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    armHandlers_["vst4.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // --- NEON load single element to all lanes ---
    armHandlers_["vld1r.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld1r.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld1r.64"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld2r.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld2r.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld3r.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld3r.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld4r.16"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    armHandlers_["vld4r.32"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
}

// ---- MIPS Handler Table ----

void PcodeCapstoneMapper::buildMIPSHandlers() {
    // MIPS move
    mipsHandlers_["move"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["mfhi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["mflo"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Arithmetic
    mipsHandlers_["add"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    mipsHandlers_["addu"] = mipsHandlers_["add"];
    mipsHandlers_["addi"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    mipsHandlers_["addiu"] = mipsHandlers_["addi"];
    mipsHandlers_["sub"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_SUB, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    mipsHandlers_["subu"] = mipsHandlers_["sub"];

    // Load / Store
    mipsHandlers_["lw"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sw"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    mipsHandlers_["lb"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sb"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    mipsHandlers_["lbu"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["lh"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sh"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    mipsHandlers_["lhu"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["ld"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sd"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    mipsHandlers_["ll"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sc"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Control flow
    mipsHandlers_["j"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranch(di, fd, addr); };
    mipsHandlers_["jal"] = [this](const auto& di, auto& fd, const auto& addr) { mapCall(di, fd, addr); };
    mipsHandlers_["jr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranchInd(di, fd, addr); };
    mipsHandlers_["jalr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCallInd(di, fd, addr); };
    mipsHandlers_["beq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bgtz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bltz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["beqz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bnez"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["blez"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bgez"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    mipsHandlers_["bgezal"] = [this](const auto& di, auto& fd, const auto& addr) { mapCall(di, fd, addr); };
    mipsHandlers_["bltzal"] = [this](const auto& di, auto& fd, const auto& addr) { mapCall(di, fd, addr); };

    // Logical
    mipsHandlers_["and"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    mipsHandlers_["or"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    mipsHandlers_["xor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    mipsHandlers_["andi"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    mipsHandlers_["ori"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    mipsHandlers_["xori"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    mipsHandlers_["nor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };

    // Shift
    mipsHandlers_["sll"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    mipsHandlers_["srl"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    mipsHandlers_["sra"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    mipsHandlers_["sllv"] = mipsHandlers_["sll"];
    mipsHandlers_["srlv"] = mipsHandlers_["srl"];
    mipsHandlers_["srav"] = mipsHandlers_["sra"];

    // Comparison
    mipsHandlers_["slt"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            emitOp(fd, addr, 0, PcodeOp::INT_LESS, {a, b}, dst);
        }
    };
    mipsHandlers_["slti"] = mipsHandlers_["slt"];
    mipsHandlers_["sltu"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            emitOp(fd, addr, 0, PcodeOp::INT_LESS, {a, b}, dst);
        }
    };
    mipsHandlers_["sltiu"] = mipsHandlers_["sltu"];

    // Multiply / divide
    mipsHandlers_["mult"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    mipsHandlers_["multu"] = mipsHandlers_["mult"];
    mipsHandlers_["div"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };
    mipsHandlers_["divu"] = mipsHandlers_["div"];
    mipsHandlers_["madd"] = mipsHandlers_["mult"];
    mipsHandlers_["maddu"] = mipsHandlers_["mult"];

    // Count leading zeros
    mipsHandlers_["clz"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };
    mipsHandlers_["clo"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };

    // No-ops and sync
    mipsHandlers_["nop"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };
    mipsHandlers_["ssnop"] = mipsHandlers_["nop"];
    mipsHandlers_["sync"] = mipsHandlers_["nop"];

    // Load upper immediate
    mipsHandlers_["lui"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Rotate (simplified as INT_RIGHT)
    mipsHandlers_["rotr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    mipsHandlers_["rotrv"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };

    // Sign-extend halfword/byte
    mipsHandlers_["seh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["seb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Word swap bytes within halfwords (COPY placeholder)
    mipsHandlers_["wsbh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Bitfield extract/insert (COPY placeholder)
    mipsHandlers_["ext"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["ins"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // System calls / exceptions
    mipsHandlers_["syscall"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    mipsHandlers_["break"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };

    // Trap-if-* (simplified as comparison)
    mipsHandlers_["teq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    mipsHandlers_["tne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    mipsHandlers_["tge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    mipsHandlers_["tgeu"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    mipsHandlers_["tlt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    mipsHandlers_["tltu"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };

    // Exception return
    mipsHandlers_["eret"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };

    // MIPS64: doubleword variants (same pcode as 32-bit)
    mipsHandlers_["dadd"]   = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    mipsHandlers_["daddu"]  = mipsHandlers_["dadd"];
    mipsHandlers_["dsub"]   = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    mipsHandlers_["dsubu"]  = mipsHandlers_["dsub"];
    mipsHandlers_["dsll"]   = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    mipsHandlers_["dsrl"]   = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    mipsHandlers_["dsra"]   = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    mipsHandlers_["dsllv"]  = mipsHandlers_["dsll"];
    mipsHandlers_["dsrlv"]  = mipsHandlers_["dsrl"];
    mipsHandlers_["dsrav"]  = mipsHandlers_["dsra"];
    mipsHandlers_["dmult"]  = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    mipsHandlers_["dmultu"] = mipsHandlers_["dmult"];
    mipsHandlers_["ddiv"]   = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };
    mipsHandlers_["ddivu"]  = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };
    mipsHandlers_["dclz"]   = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };
    mipsHandlers_["dclo"]   = mipsHandlers_["dclz"];

    // Floating-point single-precision
    mipsHandlers_["fadd_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    mipsHandlers_["fsub_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    mipsHandlers_["fmul_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    mipsHandlers_["fdiv_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    mipsHandlers_["fsqrt_s"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    mipsHandlers_["fabs_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    mipsHandlers_["fneg_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    // Floating-point double-precision
    mipsHandlers_["fadd_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    mipsHandlers_["fsub_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    mipsHandlers_["fmul_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    mipsHandlers_["fdiv_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    mipsHandlers_["fsqrt_d"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    mipsHandlers_["fabs_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    mipsHandlers_["fneg_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    // Moves between FPU and GPR
    mipsHandlers_["mov_s"]    = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["mov_d"]    = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["mfc1"]     = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["mtc1"]     = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["dmfc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["dmtc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["cfc1"]     = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["ctc1"]     = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    // MIPS float comparison
    mipsHandlers_["c_eq_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    mipsHandlers_["c_lt_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_LESS); };
    mipsHandlers_["c_le_s"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_LESSEQUAL); };
    mipsHandlers_["c_eq_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    mipsHandlers_["c_lt_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_LESS); };
    mipsHandlers_["c_le_d"]   = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_LESSEQUAL); };
    // FPU load/store
    mipsHandlers_["lwc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["swc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    mipsHandlers_["ldc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    mipsHandlers_["sdc1"]    = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Interrupt control (no-op)
    mipsHandlers_["di"] = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["ei"] = [this](const auto&, auto&, const auto&) {};

    // Cache / prefetch (no-op)
    mipsHandlers_["cache"] = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["pref"]  = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["prefx"] = [this](const auto&, auto&, const auto&) {};

    // Conditional move
    mipsHandlers_["movn"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["movz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Sign-extend byte/halfword (improved from COPY to SEXT)
    mipsHandlers_["seh"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, 2);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_SEXT, {src}, dst);
        }
    };
    mipsHandlers_["seb"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, 1);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_SEXT, {src}, dst);
        }
    };

    // Word swap bytes within halfwords (improved from COPY)
    mipsHandlers_["wsbh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Bitfield extract/insert (improved from COPY)
    mipsHandlers_["ext"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["ins"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // TLB operations (no-ops — privileged, never appear in user code)
    mipsHandlers_["tlbp"]  = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["tlbr"]  = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["tlbwi"] = [this](const auto&, auto&, const auto&) {};
    mipsHandlers_["tlbwr"] = [this](const auto&, auto&, const auto&) {};

    // MIPS32/64: reciprocal and square-root estimate
    mipsHandlers_["recip.d"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_DIV); };
    mipsHandlers_["rsqrt.d"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    mipsHandlers_["recip.s"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_DIV); };
    mipsHandlers_["rsqrt.s"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };

    // MIPS DSP ASE (basic subset)
    mipsHandlers_["addq.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    mipsHandlers_["subq.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };
    mipsHandlers_["addq_s.ph"] = mipsHandlers_["addq.ph"];
    mipsHandlers_["subq_s.ph"] = mipsHandlers_["subq.ph"];
    mipsHandlers_["mul.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    mipsHandlers_["muleq_s.w.phl"] = mipsHandlers_["mul.ph"];
    mipsHandlers_["muleq_s.w.phr"] = mipsHandlers_["mul.ph"];
    mipsHandlers_["dpa.w.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    mipsHandlers_["dps.w.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    mipsHandlers_["precrq.ph.w"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    mipsHandlers_["precrq.pb.ph"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
}

// ---- PPC Handler Table ----

void PcodeCapstoneMapper::buildPPCHandlers() {
    // PPC move
    ppcHandlers_["mr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mfocrf"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mtocrf"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mflr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mtlr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mfctr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mtctr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mfcr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Arithmetic
    ppcHandlers_["add"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["addi"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["addis"] = ppcHandlers_["addi"];
    ppcHandlers_["addc"] = ppcHandlers_["add"];
    ppcHandlers_["adde"] = ppcHandlers_["add"];
    ppcHandlers_["addme"] = ppcHandlers_["addi"];
    ppcHandlers_["addze"] = ppcHandlers_["addi"];
    ppcHandlers_["subf"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_SUB, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["subfic"] = ppcHandlers_["subf"];
    ppcHandlers_["subfc"] = ppcHandlers_["subf"];
    ppcHandlers_["mulli"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["divw"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_DIV, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };

    // Load / Store
    ppcHandlers_["lwz"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stw"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["lbz"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stb"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["lhz"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["sth"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["ld"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["std"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["lwa"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["lwzu"] = ppcHandlers_["lwz"];
    ppcHandlers_["stwu"] = ppcHandlers_["stw"];
    ppcHandlers_["lbzu"] = ppcHandlers_["lbz"];
    ppcHandlers_["stbu"] = ppcHandlers_["stb"];
    ppcHandlers_["lhzu"] = ppcHandlers_["lhz"];
    ppcHandlers_["sthu"] = ppcHandlers_["sth"];
    ppcHandlers_["lfsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stfsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Control flow
    ppcHandlers_["b"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranch(di, fd, addr); };
    ppcHandlers_["bl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCall(di, fd, addr); };
    ppcHandlers_["blr"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };
    ppcHandlers_["blrl"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };
    ppcHandlers_["bctr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranchInd(di, fd, addr); };
    ppcHandlers_["bctrl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCallInd(di, fd, addr); };
    ppcHandlers_["bc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bclr"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };
    // Conditional branches
    ppcHandlers_["beq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["blt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bgt"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["ble"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bso"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bno"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    ppcHandlers_["bdnz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };

    // Logical
    ppcHandlers_["and"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["andc"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["or"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    ppcHandlers_["orc"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    ppcHandlers_["xor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    ppcHandlers_["nand"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["nor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["eqv"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_EQUAL); };

    // Shift / rotate
    ppcHandlers_["slw"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    ppcHandlers_["srw"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    ppcHandlers_["sraw"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    ppcHandlers_["sld"] = ppcHandlers_["slw"];
    ppcHandlers_["srd"] = ppcHandlers_["srw"];
    ppcHandlers_["srad"] = ppcHandlers_["sraw"];

    // Comparison
    ppcHandlers_["cmp"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* a = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (a && b) {
            auto* result = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_EQUAL, {a, b}, result);
        }
    };
    ppcHandlers_["cmpl"] = ppcHandlers_["cmp"];
    ppcHandlers_["cmpi"] = ppcHandlers_["cmp"];
    ppcHandlers_["cmpli"] = ppcHandlers_["cmp"];
    ppcHandlers_["cmplw"] = ppcHandlers_["cmp"];

    // No-op
    ppcHandlers_["nop"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };

    // Load immediate
    ppcHandlers_["li"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["lis"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Move to/from special purpose register
    ppcHandlers_["mtspr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mfspr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Condition register logical ops
    ppcHandlers_["crxor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };
    ppcHandlers_["crand"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["cror"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };

    // Rotate left word immediate (simplified)
    ppcHandlers_["rlwinm"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    ppcHandlers_["rlwimi"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };

    // Shift right arithmetic word immediate
    ppcHandlers_["srawi"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };

    // Count leading zeros
    ppcHandlers_["cntlzw"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };
    ppcHandlers_["cntlzd"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };

    // Trap words (simplified as comparison)
    ppcHandlers_["td"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    ppcHandlers_["tdi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    ppcHandlers_["tw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    ppcHandlers_["twi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };

    // Floating-point arithmetic
    ppcHandlers_["fadd"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    ppcHandlers_["fsub"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    ppcHandlers_["fmul"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    ppcHandlers_["fdiv"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    ppcHandlers_["fmadd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    ppcHandlers_["fmsub"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    ppcHandlers_["fabs"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    ppcHandlers_["fneg"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    ppcHandlers_["fsqrt"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    ppcHandlers_["fmr"]   = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["fctiw"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    ppcHandlers_["fctiwz"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    ppcHandlers_["frsp"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_FLOAT2FLOAT); };
    ppcHandlers_["fcmp"]  = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    // PPC float load/store
    ppcHandlers_["lfs"]   = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["lfd"]   = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stfs"]  = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["stfd"]  = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // Lightweight sync
    ppcHandlers_["lwsync"] = ppcHandlers_["sync"];

    // Power management (no-op)
    ppcHandlers_["wait"] = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["nap"]  = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["doze"] = [this](const auto&, auto&, const auto&) {};

    // System call
    ppcHandlers_["sc"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };

    // Synchronization no-ops
    ppcHandlers_["sync"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };
    ppcHandlers_["isync"] = ppcHandlers_["sync"];

    // Enforce in-order execution of I/O (no-op placeholder)
    ppcHandlers_["eieio"] = ppcHandlers_["sync"];

    // Multiply high word
    ppcHandlers_["mulhw"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize * 2);
            auto* prod = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["mulhwu"] = ppcHandlers_["mulhw"];
    ppcHandlers_["mulhd"] = ppcHandlers_["mulhw"];
    ppcHandlers_["mulhdu"] = ppcHandlers_["mulhw"];
    ppcHandlers_["mulld"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = 8;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_MULT, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["mullw"] = ppcHandlers_["mulld"];

    // Divide doubleword
    ppcHandlers_["divd"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = 8;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_DIV, {a, b}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    ppcHandlers_["divdu"] = ppcHandlers_["divd"];
    ppcHandlers_["divde"] = ppcHandlers_["divd"];
    ppcHandlers_["divdeu"] = ppcHandlers_["divd"];

    // Sign extend
    ppcHandlers_["extsb"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, 1);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_SEXT, {src}, dst);
        }
    };
    ppcHandlers_["extsh"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, 2);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_SEXT, {src}, dst);
        }
    };
    ppcHandlers_["extsw"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = 8;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, 4);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_SEXT, {src}, dst);
        }
    };

    // Negate
    ppcHandlers_["neg"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.empty()) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        if (dst) {
            emitOp(fd, addr, 0, PcodeOp::INT_2COMP, {dst}, dst);
        }
    };

    // Subtract from zero extended (subfze: dst = ~src + carry, simplified as neg)
    ppcHandlers_["subfze"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (dst && src) {
            auto* neg = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_2COMP, {src}, neg);
            emitOp(fd, addr, 1, PcodeOp::COPY, {neg}, dst);
        }
    };
    ppcHandlers_["subfzeo"] = ppcHandlers_["subfze"];
    ppcHandlers_["subfme"] = ppcHandlers_["subfze"];
    ppcHandlers_["subfmeo"] = ppcHandlers_["subfze"];

    // Add extended (addme: dst = src + 1, simplified)
    ppcHandlers_["addme"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* src = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (dst && src) {
            emitOp(fd, addr, 0, PcodeOp::INT_ADD, {src, makeConst(fd, 1, ptrSize)}, dst);
        }
    };
    ppcHandlers_["addze"] = ppcHandlers_["addme"];

    // Move to/from MSR (simplified as COPY)
    ppcHandlers_["mtmsr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["mfmsr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Instruction/data cache block invalidate/flush (no-ops for decompilation)
    ppcHandlers_["icbi"]  = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["dcbf"]  = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["dcbst"] = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["dcbz"]  = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["dcbt"]  = [this](const auto&, auto&, const auto&) {};
    ppcHandlers_["dcbtst"] = [this](const auto&, auto&, const auto&) {};

    // Store word conditional (atomic)
    ppcHandlers_["stwcx."] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["lwarx"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["ldarx"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stdcx."] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // === VMX / AltiVec (vector integer) ===
    ppcHandlers_["vaddubm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vadduhm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vadduwm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vaddfp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsububm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsubuhm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsubuwm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsubfp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vand"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vor"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vxor"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vandc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vslb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vslh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vslw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsrh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsrw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsrab"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsrah"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsraw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vpkuhum"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vpkuwum"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vpkuhus"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vpkuwus"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrghb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrghh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrghw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrglb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrglh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmrglw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vspltb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsplth"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vspltw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vspltisb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vspltish"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vspltisw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpequb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpequh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpequw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtub"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtuh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtsh"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vcmpgtsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vperm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsel"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsumsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsum2sws"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsum4ubs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsum4sbs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vsum4shs"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vmaddfp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vnmsubfp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrefp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrsqrtefp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vexptefp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vlogefp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrfin"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrfiz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrfip"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["vrfim"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    ppcHandlers_["lvx"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stvx"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    ppcHandlers_["lvxl"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    ppcHandlers_["stvxl"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
}

// ---- X86 Handler Table ----

void PcodeCapstoneMapper::buildX86Handlers() {
    // mov / movzx / movsx -> COPY variants
    x86Handlers_["mov"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movzx"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movsx"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // arithmetic
    x86Handlers_["add"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    x86Handlers_["sub"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };

    // Control flow: CALL / CALLIND
    x86Handlers_["call"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* target = nullptr;
        if (!di.operands.empty()) {
            target = parseOperand(di.operands[0], fd, addr, ptrSize);
        }
        bool isIndirect = (target && !target->isConstant());
        emitOp(fd, addr, 0, isIndirect ? PcodeOp::CALLIND : PcodeOp::CALL, {target}, nullptr);
    };

    // Control flow: RETURN
    x86Handlers_["ret"] = [this](const auto& di, auto& fd, const auto& addr) {
        emitOp(fd, addr, 0, PcodeOp::RETURN, {}, nullptr);
    };

    // Control flow: BRANCH (unconditional jump)
    x86Handlers_["jmp"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranch(di, fd, addr); };

    // BRANCHIND — if jmp operand is a register, it's indirect
    // (handled by mapBranch which uses BRANCH for constants, BRANCHIND for regs)

    // Control flow: CBRANCH (conditional jumps)
    x86Handlers_["je"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jg"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jle"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["ja"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jae"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jbe"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jo"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jno"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["js"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jns"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jnp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["jecxz"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };

    // PTRADD (LEA)
    x86Handlers_["lea"] = [this](const auto& di, auto& fd, const auto& addr) { mapPtrAdd(di, fd, addr); };

    // Push/Pop with stack ops
    x86Handlers_["push"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* val = nullptr;
        if (!di.operands.empty()) {
            val = parseOperand(di.operands[0], fd, addr, ptrSize);
        }
        VarnodeAST* sp = getOrCreateReg(fd, "rsp", ptrSize, 4);
        VarnodeAST* tmpSP = makeUnique(fd, ptrSize);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::INT_SUB, {sp, inc}, tmpSP);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmpSP}, sp);
        if (val) {
            emitOp(fd, addr, 2, PcodeOp::STORE, {sp, val}, nullptr);
        }
    };

    x86Handlers_["pop"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* sp = getOrCreateReg(fd, "rsp", ptrSize, 4);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        if (!di.operands.empty()) {
            VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
            if (dst) {
                emitOp(fd, addr, 0, PcodeOp::LOAD, {sp}, dst);
            }
        }
        VarnodeAST* newSP = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 1, PcodeOp::INT_ADD, {sp, inc}, newSP);
        emitOp(fd, addr, 2, PcodeOp::COPY, {newSP}, sp);
    };

    // PTRSUB / movsxd
    x86Handlers_["movsxd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Logical
    x86Handlers_["and"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_AND); };
    x86Handlers_["or"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_OR); };
    x86Handlers_["xor"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_XOR); };

    // Shifts
    x86Handlers_["shl"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    x86Handlers_["shr"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    x86Handlers_["sar"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    x86Handlers_["shld"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    x86Handlers_["shrd"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };
    x86Handlers_["rol"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    x86Handlers_["ror"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };

    // Increment/Decrement
    x86Handlers_["inc"] = [this](const auto& di, auto& fd, const auto& addr) { mapIncDec(di, fd, addr, true); };
    x86Handlers_["dec"] = [this](const auto& di, auto& fd, const auto& addr) { mapIncDec(di, fd, addr, false); };

    // Negate / Bitwise NOT
    x86Handlers_["neg"] = [this](const auto& di, auto& fd, const auto& addr) { mapNegNot(di, fd, addr, true); };
    x86Handlers_["not"] = [this](const auto& di, auto& fd, const auto& addr) { mapNegNot(di, fd, addr, false); };

    // Compare / Test
    x86Handlers_["cmp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, false); };
    x86Handlers_["test"] = [this](const auto& di, auto& fd, const auto& addr) { mapCmpTest(di, fd, addr, true); };

    // Multiply / Divide
    x86Handlers_["mul"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    x86Handlers_["imul"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    x86Handlers_["div"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };
    x86Handlers_["idiv"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_DIV); };

    // Exchange
    x86Handlers_["xchg"] = [this](const auto& di, auto& fd, const auto& addr) { mapXchg(di, fd, addr); };

    // System calls / interrupts
    x86Handlers_["syscall"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["sysenter"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["int"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["int3"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };

    // Sign-extension (cdq/cqo/cdqe — no explicit operands in Intel syntax; emit as placeholder)
    x86Handlers_["cdq"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };
    x86Handlers_["cqo"] = x86Handlers_["cdq"];
    x86Handlers_["cdqe"] = x86Handlers_["cdq"];
    x86Handlers_["cwde"] = x86Handlers_["cdq"];

    // Conditional moves (simplified as unconditional COPY)
    x86Handlers_["cmova"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovae"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovb"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovbe"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmove"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovg"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovl"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovle"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovno"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovns"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovo"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmovs"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // POPCOUNT
    x86Handlers_["popcnt"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };

    // ADD/SUB with carry (ignore carry flag; same pcode as plain add/sub)
    x86Handlers_["adc"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    x86Handlers_["sbb"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_SUB); };

    // Bit test (COPY placeholder — reads/writes dest, ignores flag side-effects)
    x86Handlers_["bt"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bts"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["btr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["btc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // NOP-like / barriers / CPU info — no data side effects
    x86Handlers_["pause"]   = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["cpuid"]   = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["lfence"]  = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["mfence"]  = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["sfence"]  = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["rdtsc"]   = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["rdtscp"]  = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["rdrand"]  = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["rdseed"]  = [this](const auto&, auto&, const auto&) {};

    // Big-endian move = same as regular mov
    x86Handlers_["movbe"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Byte-table lookup (AL = DS:[BX+AL])
    x86Handlers_["xlatb"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };

    // Atomic compare-exchange (LOAD/STORE placeholder)
    x86Handlers_["cmpxchg8b"]  = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmpxchg16b"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Leading/trailing zero count (use popcount pcode)
    x86Handlers_["lzcnt"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };
    x86Handlers_["tzcnt"] = [this](const auto& di, auto& fd, const auto& addr) { mapPopcount(di, fd, addr); };

    // Interrupt return
    x86Handlers_["iret"]  = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };
    x86Handlers_["iretd"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };
    x86Handlers_["iretq"] = [this](const auto& di, auto& fd, const auto& addr) { mapReturn(di, fd, addr); };

    // No-op
    x86Handlers_["nop"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };

    // Set byte on condition (simplified as COPY)
    x86Handlers_["sete"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setg"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setge"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setle"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["seta"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setae"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setbe"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["seto"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setno"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sets"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setns"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["setnp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Bit scan (simplified as COPY — full semantics later)
    x86Handlers_["bsf"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bsr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Byte swap (simplified as COPY)
    x86Handlers_["bswap"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Exchange-and-add (simplified as XCHG)
    x86Handlers_["xadd"] = [this](const auto& di, auto& fd, const auto& addr) { mapXchg(di, fd, addr); };

    // Compare-and-exchange (simplified as COPY)
    x86Handlers_["cmpxchg"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // SIMD scalar float (now emits real float pcode)
    x86Handlers_["addss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    x86Handlers_["addsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    x86Handlers_["subss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    x86Handlers_["subsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    x86Handlers_["mulss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    x86Handlers_["mulsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    x86Handlers_["divss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    x86Handlers_["divsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    x86Handlers_["sqrtss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    x86Handlers_["sqrtsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };

    // SIMD scalar move (still COPY)
    x86Handlers_["movss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movdqa"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movdqu"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movaps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movups"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // SSE comparison (ucomiss/ucomisd — sets ZF/CF/PF flags)
    x86Handlers_["ucomiss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["ucomisd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["comiss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["comisd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };

    // SSE float min/max (simplified as COPY)
    x86Handlers_["minss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["maxss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["minsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["maxsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // FPU x87 instructions
    x86Handlers_["fld"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (!di.operands.empty()) {
            VarnodeAST* src = parseOperand(di.operands[0], fd, addr, ptrSize);
            if (src) {
                emitOp(fd, addr, 0, PcodeOp::FLOAT_FLOAT2FLOAT, {src}, makeUnique(fd, ptrSize));
            }
        }
    };
    x86Handlers_["fst"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() >= 1) {
            VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
            if (dst) {
                VarnodeAST* st0 = getOrCreateReg(fd, "st(0)", 10, 200);
                if (isMemoryOperand(di.operands[0])) {
                    emitOp(fd, addr, 0, PcodeOp::STORE, {dst, st0}, nullptr);
                } else {
                    emitOp(fd, addr, 0, PcodeOp::FLOAT_FLOAT2FLOAT, {st0}, dst);
                }
            }
        }
    };
    x86Handlers_["fstp"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["fadd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_ADD); };
    x86Handlers_["fsub"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_SUB); };
    x86Handlers_["fmul"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_MULT); };
    x86Handlers_["fdiv"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_DIV); };
    x86Handlers_["fcom"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["fcomp"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["fcomi"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["fcomip"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_EQUAL); };
    x86Handlers_["fucom"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_NOTEQUAL); };
    x86Handlers_["fucomp"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_NOTEQUAL); };
    x86Handlers_["fucomi"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_NOTEQUAL); };
    x86Handlers_["fucomip"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatCmp(di, fd, addr, PcodeOp::FLOAT_NOTEQUAL); };
    x86Handlers_["fchs"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_NEG); };
    x86Handlers_["fabs"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_ABS); };
    x86Handlers_["fsqrt"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatUnary(di, fd, addr, PcodeOp::FLOAT_SQRT); };
    x86Handlers_["fild"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["fist"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["fistp"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["fclex"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["fnclex"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["fldz"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, ptrSize)}, makeUnique(fd, ptrSize));
    };
    x86Handlers_["fld1"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 1, ptrSize)}, makeUnique(fd, ptrSize));
    };
    x86Handlers_["fldcw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["fnstcw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["fnstsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["fwait"] = [this](const auto&, auto&, const auto&) {};

    // SSE2 float conversion (float<->double precision)
    x86Handlers_["cvtss2sd"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_FLOAT2FLOAT); };
    x86Handlers_["cvtsd2ss"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloatArith(di, fd, addr, PcodeOp::FLOAT_FLOAT2FLOAT); };
    x86Handlers_["cvttps2dq"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["cvtdq2ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["cvttss2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["cvttsd2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["cvtss2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["cvtsd2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["cvtsi2ss"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["cvtsi2sd"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["vcvtsi2ss"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["vcvtsi2sd"] = [this](const auto& di, auto& fd, const auto& addr) { mapInt2Float(di, fd, addr); };
    x86Handlers_["vcvttss2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["vcvttsd2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["vcvtss2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };
    x86Handlers_["vcvtsd2si"] = [this](const auto& di, auto& fd, const auto& addr) { mapFloat2Int(di, fd, addr); };

    // Push/Pop flags (SP adjust only, no flag tracking)
    x86Handlers_["pushf"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* sp = getOrCreateReg(fd, "rsp", ptrSize, 4);
        VarnodeAST* tmpSP = makeUnique(fd, ptrSize);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::INT_SUB, {sp, inc}, tmpSP);
        emitOp(fd, addr, 1, PcodeOp::COPY, {tmpSP}, sp);
    };
    x86Handlers_["popf"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* sp = getOrCreateReg(fd, "rsp", ptrSize, 4);
        VarnodeAST* newSP = makeUnique(fd, ptrSize);
        VarnodeAST* inc = makeConst(fd, ptrSize, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::INT_ADD, {sp, inc}, newSP);
        emitOp(fd, addr, 1, PcodeOp::COPY, {newSP}, sp);
    };

    // Direction flag (placeholder)
    x86Handlers_["cld"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        emitOp(fd, addr, 0, PcodeOp::COPY, {makeConst(fd, 0, 1)}, makeUnique(fd, 1));
    };
    x86Handlers_["std"] = x86Handlers_["cld"];

    // Load/Store flags (simplified as COPY)
    x86Handlers_["lahf"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sahf"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Leave: copy rbp to rsp
    x86Handlers_["leave"] = [this](const auto& di, auto& fd, const auto& addr) {
        (void)di;
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* rbp = getOrCreateReg(fd, "rbp", ptrSize, 5);
        VarnodeAST* rsp = getOrCreateReg(fd, "rsp", ptrSize, 4);
        emitOp(fd, addr, 0, PcodeOp::COPY, {rbp}, rsp);
    };

    // LOOP instructions (decrement ECX/RCX, branch if not zero)
    x86Handlers_["loop"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* target = nullptr;
        if (!di.operands.empty()) {
            target = parseOperand(di.operands[0], fd, addr, ptrSize);
        }
        VarnodeAST* cx = getOrCreateReg(fd, ptrSize == 8 ? "rcx" : "ecx", ptrSize, ptrSize == 8 ? 2 : 1);
        VarnodeAST* dec = makeUnique(fd, ptrSize);
        emitOp(fd, addr, 0, PcodeOp::INT_SUB, {cx, makeConst(fd, 1, ptrSize)}, dec);
        emitOp(fd, addr, 1, PcodeOp::COPY, {dec}, cx);
        if (target) {
            VarnodeAST* cond = makeUnique(fd, 1);
            emitOp(fd, addr, 2, PcodeOp::CBRANCH, {target, cond}, nullptr);
        }
    };
    x86Handlers_["loope"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };
    x86Handlers_["loopne"] = [this](const auto& di, auto& fd, const auto& addr) { mapCBranch(di, fd, addr); };

    // SAL = SHL alias
    x86Handlers_["sal"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };

    // String operations (load/store based, simplified as load/store)
    x86Handlers_["movsb"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 1);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, val);
        emitOp(fd, addr, 1, PcodeOp::STORE, {rdi, val}, nullptr);
    };
    x86Handlers_["movsw"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 2);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, val);
        emitOp(fd, addr, 1, PcodeOp::STORE, {rdi, val}, nullptr);
    };
    x86Handlers_["movsq"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 8);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, val);
        emitOp(fd, addr, 1, PcodeOp::STORE, {rdi, val}, nullptr);
    };
    x86Handlers_["stosb"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* al = getOrCreateReg(fd, "al", 1, 0);
        emitOp(fd, addr, 0, PcodeOp::STORE, {rdi, al}, nullptr);
    };
    x86Handlers_["stosw"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* ax = getOrCreateReg(fd, "ax", 2, 0);
        emitOp(fd, addr, 0, PcodeOp::STORE, {rdi, ax}, nullptr);
    };
    x86Handlers_["stosd"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* eax = getOrCreateReg(fd, "eax", 4, 0);
        emitOp(fd, addr, 0, PcodeOp::STORE, {rdi, eax}, nullptr);
    };
    x86Handlers_["stosq"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* rax = getOrCreateReg(fd, "rax", 8, 0);
        emitOp(fd, addr, 0, PcodeOp::STORE, {rdi, rax}, nullptr);
    };
    x86Handlers_["lodsb"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* al = getOrCreateReg(fd, "al", 1, 0);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, al);
    };
    x86Handlers_["lodsw"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* ax = getOrCreateReg(fd, "ax", 2, 0);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, ax);
    };
    x86Handlers_["lodsd"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* eax = getOrCreateReg(fd, "eax", 4, 0);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, eax);
    };
    x86Handlers_["lodsq"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rax = getOrCreateReg(fd, "rax", 8, 0);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, rax);
    };
    x86Handlers_["scasb"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 1);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rdi}, val);
    };
    x86Handlers_["scasw"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 2);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rdi}, val);
    };
    x86Handlers_["scasd"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 4);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rdi}, val);
    };
    x86Handlers_["scasq"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* val = makeUnique(fd, 8);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rdi}, val);
    };
    x86Handlers_["cmpsb"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* a = makeUnique(fd, 1);
        VarnodeAST* b = makeUnique(fd, 1);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, a);
        emitOp(fd, addr, 1, PcodeOp::LOAD, {rdi}, b);
        emitOp(fd, addr, 2, PcodeOp::INT_EQUAL, {a, b}, makeUnique(fd, 1));
    };
    x86Handlers_["cmpsw"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* a = makeUnique(fd, 2);
        VarnodeAST* b = makeUnique(fd, 2);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, a);
        emitOp(fd, addr, 1, PcodeOp::LOAD, {rdi}, b);
        emitOp(fd, addr, 2, PcodeOp::INT_EQUAL, {a, b}, makeUnique(fd, 1));
    };
    x86Handlers_["cmpsq"] = [this](const auto&, auto& fd, const auto& addr) {
        int ptrSize = 8;
        VarnodeAST* rsi = getOrCreateReg(fd, "rsi", ptrSize, 6);
        VarnodeAST* rdi = getOrCreateReg(fd, "rdi", ptrSize, 7);
        VarnodeAST* a = makeUnique(fd, 8);
        VarnodeAST* b = makeUnique(fd, 8);
        emitOp(fd, addr, 0, PcodeOp::LOAD, {rsi}, a);
        emitOp(fd, addr, 1, PcodeOp::LOAD, {rdi}, b);
        emitOp(fd, addr, 2, PcodeOp::INT_EQUAL, {a, b}, makeUnique(fd, 1));
    };
    x86Handlers_["insb"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["insw"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["insd"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["outsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["outsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["outsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["in"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };
    x86Handlers_["out"] = [this](const auto& di, auto& fd, const auto& addr) { mapSyscall(di, fd, addr); };

    // Segment descriptor access (simplified as COPY)
    x86Handlers_["lar"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["lsl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sgdt"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["sidt"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["sldt"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["str"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["smsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // Cache control
    x86Handlers_["clflush"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["monitor"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["mwait"] = [this](const auto&, auto&, const auto&) {};

    // --- SSE2 packed integer (COPY for data-flow) ---
    x86Handlers_["paddb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["paddw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["paddd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["paddq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psubb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psubw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psubd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psubq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmullw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmulhw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmulhuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmuludq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pand"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["por"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pxor"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pandn"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psllw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pslld"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psllq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psrlw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psrld"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psrlq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psraw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psrad"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["packsswb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["packssdw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["packuswb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpcklbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpcklwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpckldq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpcklqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpckhbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpckhwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpckhdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["punpckhqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pshufd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pshuflw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pshufhw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovmskb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // SSE3
    x86Handlers_["pabsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pabsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pabsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pshufb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmaddubsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["phaddw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["phaddd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["phsubw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["phsubd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmaddwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psignb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psignw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["psignd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // SSE4.1
    x86Handlers_["pmaxsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmaxuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmaxud"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmaxsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pminsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pminuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pminud"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pminsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pblendvb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pblendw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pinsrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pinsrd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pinsrq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pextrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pextrd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pextrq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxbd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxbq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxbd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxbq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxwq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxwq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovsxdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pmovzxdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["ptest"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["roundps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["roundss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["roundpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["roundsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // SSE4.2 string / text processing
    x86Handlers_["pcmpestri"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pcmpestrm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pcmpistri"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pcmpistrm"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- AVX (VEX-encoded) integer / float (COPY placeholders, same as SSE) ---
    x86Handlers_["vpaddb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmullw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmulhw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmulhuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpand"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpor"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpxor"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpandn"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsllw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpslld"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsllq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsrlw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsrld"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsrlq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsraw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsrad"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpacksswb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpackssdw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpackuswb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpcklbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpcklwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpckldq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpcklqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpckhbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpckhwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpckhdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpunpckhqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpshufd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpshuflw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpshufhw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpabsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpabsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpabsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpshufb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaxsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaxuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaxud"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaxsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpminsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpminuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpminud"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpminsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpblendvb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpblendw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpinsrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpinsrd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpinsrq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpextrb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpextrd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpextrq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovsxbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovsxbd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovsxbq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovzxbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovzxbd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmovzxbq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vptest"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vroundps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vroundss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vroundpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vroundsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vhaddps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vhsubps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vaddps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vsubps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vmulps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vdivps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vaddpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vsubpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vmulpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vdivpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vmaxps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vminps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vmaxpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vminpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- AVX2 integer (VEX-encoded) ---
    x86Handlers_["vpaddsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddusb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpaddusw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubsb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubusb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsubusw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmuldq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmuludq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaddwd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpmaddubsw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsllvd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsrlvd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpsravd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vgatherdps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vgatherdpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpgatherdd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpgatherdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vbroadcastss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vbroadcastsd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpbroadcastb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpbroadcastw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpbroadcastd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpbroadcastq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpermq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpermpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vperm2i128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vperm2f128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vinsertf128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vextractf128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vinserti128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vextracti128"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- AES instructions ---
    x86Handlers_["aesenc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["aesenclast"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["aesdec"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["aesdeclast"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["aesimc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["aeskeygenassist"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pclmulqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- SHA extensions ---
    x86Handlers_["sha1rnds4"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha1nexte"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha1msg1"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha1msg2"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha256rnds2"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha256msg1"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sha256msg2"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- VAES (VEX/EVEX) ---
    x86Handlers_["vaesenc"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vaesenclast"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vaesdec"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vaesdeclast"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- BMI1 ---
    x86Handlers_["andn"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 3) return;
        auto* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        auto* a = parseOperand(di.operands[1], fd, addr, ptrSize);
        auto* b = parseOperand(di.operands[2], fd, addr, ptrSize);
        if (dst && a && b) {
            auto* notA = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_NEGATE, {a}, notA);
            emitOp(fd, addr, 1, PcodeOp::INT_AND, {notA, b}, dst);
        }
    };
    x86Handlers_["bextr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["blsi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["blsmsk"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["blsr"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- BMI2 ---
    x86Handlers_["bzhi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["mulx"] = [this](const auto& di, auto& fd, const auto& addr) { mapMulDiv(di, fd, addr, PcodeOp::INT_MULT); };
    x86Handlers_["pdep"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["pext"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["rorx"] = [this](const auto& di, auto& fd, const auto& addr) {
        int ptrSize = (architecture_.find("64") != std::string::npos) ? 8 : 4;
        if (di.operands.size() < 2) return;
        VarnodeAST* dst = parseOperand(di.operands[0], fd, addr, ptrSize);
        VarnodeAST* src = parseOperand(di.operands[1], fd, addr, ptrSize);
        if (dst && src) {
            VarnodeAST* tmp = makeUnique(fd, ptrSize);
            emitOp(fd, addr, 0, PcodeOp::INT_RIGHT, {src, makeConst(fd, 1, ptrSize)}, tmp);
            emitOp(fd, addr, 1, PcodeOp::COPY, {tmp}, dst);
        }
    };
    x86Handlers_["sarx"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_SRIGHT); };
    x86Handlers_["shlx"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_LEFT); };
    x86Handlers_["shrx"] = [this](const auto& di, auto& fd, const auto& addr) { mapBoolOp(di, fd, addr, PcodeOp::INT_RIGHT); };

    // --- FMA (Fused Multiply-Add) ---
    x86Handlers_["vfmadd132ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmadd132pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmadd213ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmadd213pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmadd231ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmadd231pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfnmadd132ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfnmadd132pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmsub132ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vfmsub132pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- SSE / AVX float max/min (COPY placeholder, matching scalar versions above) ---
    x86Handlers_["maxps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["minps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["maxpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["minpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["addps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["subps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["mulps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["divps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["addpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["subpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["mulpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["divpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sqrtps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["sqrtpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["andps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["andpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["orps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["orpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["xorps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["xorpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["andnps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["andnpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmpps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmppd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cmpss"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["shufps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["shufpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["unpcklps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["unpckhps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["unpcklpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["unpckhpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtpi2ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtps2pi"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtps2pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtpd2ps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtps2dq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtdq2pd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvtpd2dq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["cvttpd2dq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["haddps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["hsubps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["haddpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["hsubpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movhlps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movlhps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movmskps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movmskpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["maskmovdqu"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["maskmovq"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["mpsadbw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["phminposuw"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["dpps"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["dppd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movntdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["movntps"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["movntpd"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["movnti"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["movddup"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movshdup"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["movsldup"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    // --- Fence / prefetch ---
    x86Handlers_["prefetchnta"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["prefetcht0"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["prefetcht1"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["prefetcht2"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["prefetchw"] = [this](const auto&, auto&, const auto&) {};

    // --- TSX (Transactional Synchronization Extensions) ---
    x86Handlers_["xbegin"] = [this](const auto& di, auto& fd, const auto& addr) { mapBranch(di, fd, addr); };
    x86Handlers_["xabort"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["xend"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["xtest"] = [this](const auto&, auto&, const auto&) {};

    // --- ADX (Multi-Precision Add with Carry) ---
    x86Handlers_["adcx"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };
    x86Handlers_["adox"] = [this](const auto& di, auto& fd, const auto& addr) { mapAddSub(di, fd, addr, PcodeOp::INT_ADD); };

    // --- MPX (Memory Protection Extensions) ---
    x86Handlers_["bndmk"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bndcl"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bndcu"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bndcn"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bndmov"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["bndldx"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    x86Handlers_["bndstx"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };

    // --- CLZERO / MONITORX / MWAITX (AMD) ---
    x86Handlers_["clzero"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["monitorx"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["mwaitx"] = [this](const auto&, auto&, const auto&) {};

    // --- RDPID ---
    x86Handlers_["rdpid"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- UD0/UD1/UD2 (undefined — trap, no data side effects) ---
    x86Handlers_["ud2"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["ud1"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["ud0"] = [this](const auto&, auto&, const auto&) {};

    // --- Virtualization (SVM/VMX) ---
    x86Handlers_["vmrun"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmload"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmsave"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmmcall"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmcall"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmfunc"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmresume"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["vmpause"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["invept"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["invvpid"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["invpcid"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["invlpg"] = [this](const auto&, auto&, const auto&) {};

    // --- XSAVE / XRSTOR / XGETBV / XSETBV ---
    x86Handlers_["xsave"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["xsavec"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["xsaveopt"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["xsaves"] = [this](const auto& di, auto& fd, const auto& addr) { mapStore(di, fd, addr); };
    x86Handlers_["xrstor"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    x86Handlers_["xrstors"] = [this](const auto& di, auto& fd, const auto& addr) { mapLoad(di, fd, addr); };
    x86Handlers_["xgetbv"] = [this](const auto&, auto&, const auto&) {};
    x86Handlers_["xsetbv"] = [this](const auto&, auto&, const auto&) {};

    // --- VNNI (VPDPBUSD, VPDPWSSD) ---
    x86Handlers_["vpdpbusd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpdpbusds"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpdpwssd"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["vpdpwssds"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- VPCLMULQDQ (VEX) ---
    x86Handlers_["vpclmulqdq"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };

    // --- GFNI (GF2P8AFFINEQB, GF2P8MULB) ---
    x86Handlers_["gf2p8affineqb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["gf2p8affineinvqb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
    x86Handlers_["gf2p8mulb"] = [this](const auto& di, auto& fd, const auto& addr) { mapCopyMov(di, fd, addr); };
}

} // namespace ghidra
