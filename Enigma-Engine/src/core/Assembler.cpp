#include "ghidra/Assembler.h"
#include <algorithm>
#include <sstream>
#include <cctype>
#include <cmath>

namespace ghidra {

const std::unordered_map<std::string, int> Assembler::regMap_ = {
    {"RAX", 0}, {"RCX", 1}, {"RDX", 2}, {"RBX", 3},
    {"RSP", 4}, {"RBP", 5}, {"RSI", 6}, {"RDI", 7},
    {"R8", 8}, {"R9", 9}, {"R10", 10}, {"R11", 11},
    {"R12", 12}, {"R13", 13}, {"R14", 14}, {"R15", 15},
    {"EAX", 0}, {"ECX", 1}, {"EDX", 2}, {"EBX", 3},
    {"ESP", 4}, {"EBP", 5}, {"ESI", 6}, {"EDI", 7},
    {"R8D", 8}, {"R9D", 9}, {"R10D", 10}, {"R11D", 11},
    {"R12D", 12}, {"R13D", 13}, {"R14D", 14}, {"R15D", 15},
    {"AX", 0}, {"CX", 1}, {"DX", 2}, {"BX", 3},
    {"SP", 4}, {"BP", 5}, {"SI", 6}, {"DI", 7},
    {"R8W", 8}, {"R9W", 9}, {"R10W", 10}, {"R11W", 11},
    {"R12W", 12}, {"R13W", 13}, {"R14W", 14}, {"R15W", 15},
    {"AL", 0}, {"CL", 1}, {"DL", 2}, {"BL", 3},
    {"SPL", 4}, {"BPL", 5}, {"SIL", 6}, {"DIL", 7},
    {"R8B", 8}, {"R9B", 9}, {"R10B", 10}, {"R11B", 11},
    {"R12B", 12}, {"R13B", 13}, {"R14B", 14}, {"R15B", 15},
    {"RIP", -1}
};

Assembler::Assembler() = default;

Assembler& Assembler::instance() {
    static Assembler inst;
    return inst;
}

// Intel-recommended multi-byte NOP encodings (from Intel Optimization Manual)
// Each entry is {size, encoding bytes}
static const std::vector<std::pair<size_t, std::vector<uint8_t>>> kMultiByteNops = {
    {9, {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {8, {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {7, {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00}},
    {6, {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}},
    {5, {0x0F, 0x1F, 0x44, 0x00, 0x00}},
    {4, {0x0F, 0x1F, 0x40, 0x00}},
    {3, {0x0F, 0x1F, 0x00}},
    {2, {0x66, 0x90}},
    {1, {0x90}},
};

std::vector<uint8_t> Assembler::generateMultiByteNop(size_t size) {
    if (size == 0) return {};
    std::vector<uint8_t> result;
    result.reserve(size);
    size_t remaining = size;
    while (remaining > 0) {
        for (auto& [nopSize, encoding] : kMultiByteNops) {
            if (nopSize <= remaining) {
                result.insert(result.end(), encoding.begin(), encoding.end());
                remaining -= nopSize;
                break;
            }
        }
    }
    return result;
}

void Assembler::fillMultiByteNopGap(std::vector<uint8_t>& out, size_t gapSize) {
    auto nops = generateMultiByteNop(gapSize);
    out.insert(out.end(), nops.begin(), nops.end());
}

std::string Assembler::toUpper(std::string s) const {
    std::transform(s.begin(), s.end(), s.begin(), ::toupper);
    return s;
}

std::string Assembler::trim(const std::string& s) const {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

Assembler::Token Assembler::tokenize(const std::string& text) const {
    Token t;
    std::string s = trim(text);
    size_t space = s.find_first_of(" \t");
    if (space == std::string::npos) {
        t.mnemonic = toUpper(s);
    } else {
        t.mnemonic = toUpper(s.substr(0, space));
        t.mnemonic.erase(std::remove(t.mnemonic.begin(), t.mnemonic.end(), ','), t.mnemonic.end());
        t.operands = trim(s.substr(space + 1));
    }
    return t;
}

std::vector<std::string> Assembler::splitOperands(const std::string& ops) const {
    std::vector<std::string> result;
    std::string current;
    int parenDepth = 0;
    for (char c : ops) {
        if (c == '(' || c == '[') ++parenDepth;
        else if (c == ')' || c == ']') --parenDepth;
        if (c == ',' && parenDepth == 0) {
            result.push_back(trim(current));
            current.clear();
        } else {
            current += c;
        }
    }
    if (!current.empty()) result.push_back(trim(current));
    return result;
}

bool Assembler::parseRegister(const std::string& s, int& reg, int& size) const {
    std::string up = toUpper(trim(s));
    auto it = regMap_.find(up);
    if (it == regMap_.end()) return false;
    reg = it->second;
    if (up.size() == 2 && up[1] == 'X') {
        if (up[0] == 'R') size = 8;
        else if (up[0] == 'E' || up == "AX" || up == "CX" || up == "DX" || up == "BX" ||
                 up == "SP" || up == "BP" || up == "SI" || up == "DI") {
            if (up[0] == 'E') size = 4;
            else size = 2;
        } else size = 2;
    } else if (up.size() == 3 && up[2] == 'X') {
        if (up[0] == 'R') size = 8;
        else size = 4;
    } else if (up.size() == 2 && (up[1] == 'L' || up[1] == 'H')) {
        size = 1;
    } else if (up.size() == 3 && up[2] == 'L') {
        size = 1;
    } else if (up.size() == 3 && up[2] == 'W') {
        size = 2;
    } else if (up.size() == 3 && up[2] == 'D') {
        size = 4;
    } else if (up == "RAX" || up == "RCX" || up == "RDX" || up == "RBX" ||
               up == "RSP" || up == "RBP" || up == "RSI" || up == "RDI" ||
               up == "R8" || up == "R9" ||
               (up.size() >= 3 && up[0] == 'R' && up[1] >= '0' && up[1] <= '9')) {
        size = 8;
    } else {
        size = 4;
    }
    return true;
}

bool Assembler::parseMemory(const std::string& s, int& base, int& index, int& scale, int64_t& disp, int& size, bool& ripRelative) const {
    std::string inner = trim(s);
    if (inner.front() == '[' && inner.back() == ']')
        inner = inner.substr(1, inner.size() - 2);
    inner = trim(inner);

    base = -1; index = -1; scale = 1; disp = 0; size = 8; ripRelative = false;

    if (inner.empty()) return true;

    // Handle [RIP] and [RIP+disp32]
    std::string upperInner = toUpper(inner);
    if (upperInner.size() >= 3 && upperInner.substr(0, 3) == "RIP") {
        ripRelative = true;
        std::string rest = trim(inner.substr(3));
        if (!rest.empty()) {
            bool neg = false;
            if (rest[0] == '+') rest = trim(rest.substr(1));
            else if (rest[0] == '-') { neg = true; rest = trim(rest.substr(1)); }
            char* end = nullptr;
            long long d = std::strtoll(rest.c_str(), &end, 0);
            if (end != rest.c_str()) disp = neg ? -d : d;
        }
        return true;
    }

    // Parse size prefix like "QWORD PTR"
    std::string remaining = inner;
    static const std::vector<std::pair<std::string, int>> sizePrefixes = {
        {"BYTE PTR", 1}, {"WORD PTR", 2}, {"DWORD PTR", 4}, {"QWORD PTR", 8},
        {"BYTE", 1}, {"WORD", 2}, {"DWORD", 4}, {"QWORD", 8}
    };
    for (auto& [prefix, sz] : sizePrefixes) {
        if (remaining.size() >= prefix.size() &&
            toUpper(remaining.substr(0, prefix.size())) == prefix) {
            size = sz;
            remaining = trim(remaining.substr(prefix.size()));
            break;
        }
    }

    // Strip brackets if present (e.g. after "DWORD PTR" extraction leaves "[RAX]")
    if (!remaining.empty() && remaining.front() == '[' && remaining.back() == ']')
        remaining = trim(remaining.substr(1, remaining.size() - 2));

    // Tokenize: split by + and - while respecting * for index*scale
    // Each token is: a register, register*scale, or integer displacement
    struct MemToken {
        bool isNegative;
        std::string text;
    };
    std::vector<MemToken> tokens;
    {
        std::string current;
        bool neg = false;
        for (size_t i = 0; i <= remaining.size(); ++i) {
            char c = (i < remaining.size()) ? remaining[i] : '\0';
            if (c == '+' || c == '-' || c == '\0') {
                if (!current.empty()) {
                    tokens.push_back({neg, trim(current)});
                }
                current.clear();
                neg = (c == '-');
            } else if (c == '*' && current.empty()) {
                // '*' immediately after '+'/'-' means the sign belongs to the index token
                // e.g. "+ RCX*4" — we handle this by keeping neg with previous token
                current += c;
            } else {
                current += c;
            }
        }
    }

    // Parse each token
    for (auto& tok : tokens) {
        int64_t tokVal;
        // Check for index*scale (contains '*')
        size_t starPos = tok.text.find('*');
        if (starPos != std::string::npos) {
            std::string left = trim(tok.text.substr(0, starPos));
            std::string right = trim(tok.text.substr(starPos + 1));
            int regNum, regSize;
            if (parseRegister(left, regNum, regSize)) {
                index = regNum;
                scale = std::atoi(right.c_str());
                if (scale != 1 && scale != 2 && scale != 4 && scale != 8) scale = 1;
            }
            continue;
        }
        // Check if it's a register
        int regNum, regSize;
        if (parseRegister(tok.text, regNum, regSize)) {
            if (base == -1) base = regNum;
            else index = regNum;
            continue;
        }
        // It's an immediate displacement
        char* end = nullptr;
        long long d = std::strtoll(tok.text.c_str(), &end, 0);
        if (end != tok.text.c_str()) {
            disp += tok.isNegative ? -d : d;
        }
    }
    return true;
}

bool Assembler::parseImmediate(const std::string& s, int64_t& val) const {
    std::string t = trim(s);
    if (t.empty()) return false;

    // Handle hex with 0x prefix — use strtoull for full 64-bit range
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
        unsigned long long uval = std::strtoull(t.c_str(), nullptr, 16);
        val = static_cast<int64_t>(uval);
        return true;
    }
    // Handle negative
    if (t[0] == '-') {
        val = std::strtoll(t.c_str(), nullptr, 0);
        return true;
    }
    // Handle decimal — also use strtoull to avoid overflow
    char* end = nullptr;
    unsigned long long uval = std::strtoull(t.c_str(), &end, 0);
    if (end != t.c_str()) {
        val = static_cast<int64_t>(uval);
        return true;
    }
    return false;
}

void Assembler::emitRex(std::vector<uint8_t>& out, int w, int r, int x, int b) const {
    if (!w && !r && !x && !b) return;
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    out.push_back(rex);
}

void Assembler::emitModRM(std::vector<uint8_t>& out, int mod, int reg, int rm) const {
    out.push_back(static_cast<uint8_t>((mod << 6) | ((reg & 7) << 3) | (rm & 7)));
}

void Assembler::emitSib(std::vector<uint8_t>& out, int scale, int index, int rm) const {
    int s = 0;
    if (scale == 2) s = 1;
    else if (scale == 4) s = 2;
    else if (scale == 8) s = 3;
    out.push_back(static_cast<uint8_t>((s << 6) | ((index & 7) << 3) | (rm & 7)));
}

void Assembler::emitDisp(std::vector<uint8_t>& out, int dispSize, int64_t disp) const {
    if (dispSize == 0) return;
    for (int i = 0; i < dispSize; ++i)
        out.push_back(static_cast<uint8_t>((disp >> (i * 8)) & 0xFF));
}

void Assembler::emitImm(std::vector<uint8_t>& out, int immSize, int64_t val) const {
    for (int i = 0; i < immSize; ++i)
        out.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

AsmResult Assembler::assemble(const std::string& text, uint64_t address) {
    std::string trimmed = trim(text);
    if (trimmed.empty()) return {false, {}, "empty input", false, {}};

    Token tok = tokenize(trimmed);
    std::vector<std::string> operands;
    if (!tok.operands.empty())
        operands = splitOperands(tok.operands);

    return assembleOne(tok.mnemonic, operands, address);
}

AsmResult Assembler::assembleOne(const std::string& mnemonic,
                                  const std::vector<std::string>& operands,
                                  uint64_t address) const {
    if (mnemonic == "NOP" || mnemonic == "NOOP") return asmNop(operands);
    if (mnemonic == "RET" || mnemonic == "RETN") return asmRet(operands);
    if (mnemonic == "INT3") return asmInt3(operands);
    if (mnemonic == "PUSH") return asmPushPop("PUSH", operands);
    if (mnemonic == "POP") return asmPushPop("POP", operands);
    if (mnemonic == "MOV") return asmMov(operands, address);
    if (mnemonic == "LEA") return asmLea(operands, address);
    if (mnemonic == "XOR") return asmXor(operands);
    if (mnemonic == "TEST") return asmTest(operands);
    if (mnemonic == "INC") return asmIncDec("INC", operands);
    if (mnemonic == "DEC") return asmIncDec("DEC", operands);
    if (mnemonic == "JMP" || mnemonic == "JMPNEAR") return asmJmp(operands, address);
    if (mnemonic == "CALL") return asmCall(operands, address);
    if (mnemonic == "MOVZX") return asmMovzx(operands);
    if (mnemonic == "MOVSX") return asmMovsx(operands);
    if (mnemonic == "IMUL") return asmImul(operands);
    if (mnemonic == "ADD" || mnemonic == "SUB" || mnemonic == "AND" ||
        mnemonic == "OR" || mnemonic == "CMP" || mnemonic == "TEST")
        return asmArith(mnemonic, operands);
    if (mnemonic == "XCHG") return asmXchg(operands);
    if (mnemonic == "BSWAP") return asmBswap(operands);
    if (mnemonic == "CDQ") return {true, {0x99}, ""};
    if (mnemonic == "CQO") return {true, {0x48, 0x99}, ""};
    if (mnemonic.size() >= 3 && mnemonic.size() <= 4 && mnemonic.substr(0, 3) == "SET")
        return asmSetcc(mnemonic, operands);
    if (mnemonic.size() >= 2 && mnemonic.size() <= 4 && mnemonic[0] == 'J' && mnemonic != "JMP" && mnemonic != "JMPNEAR")
        return asmJcc(mnemonic, operands, address);

    return {false, {}, "unknown mnemonic: " + mnemonic, false, {}};
}

AsmResult Assembler::asmNop(const std::vector<std::string>& ops) const {
    return {true, {0x90}, ""};
}

AsmResult Assembler::asmRet(const std::vector<std::string>& ops) const {
    return {true, {0xC3}, ""};
}

AsmResult Assembler::asmInt3(const std::vector<std::string>& ops) const {
    return {true, {0xCC}, ""};
}

AsmResult Assembler::asmPushPop(const std::string& mnem, const std::vector<std::string>& ops) const {
    if (ops.empty()) return {false, {}, mnem + ": missing operand", false, {}};
    int reg, size;
    if (!parseRegister(ops[0], reg, size))
        return {false, {}, mnem + ": invalid register", false, {}};

    if (reg < 8) {
        uint8_t opcode = (mnem == "PUSH") ? (0x50 + reg) : (0x58 + reg);
        return {true, {opcode}, ""};
    }
    std::vector<uint8_t> bytes;
    emitRex(bytes, 0, 0, 0, reg >= 8);
    bytes.push_back((mnem == "PUSH") ? (0x50 + (reg & 7)) : (0x58 + (reg & 7)));
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmMov(const std::vector<std::string>& ops, uint64_t address) const {
    if (ops.size() != 2) return {false, {}, "MOV: expected 2 operands", false, {}};
    int dstReg, dstSize;
    int srcReg, srcSize;
    int64_t imm;
    bool dstIsReg = parseRegister(ops[0], dstReg, dstSize);
    bool srcIsReg = parseRegister(ops[1], srcReg, srcSize);
    bool srcIsImm = !srcIsReg && parseImmediate(ops[1], imm);
    int base, index, scale, memSize;
    int64_t disp;
    bool dstIsMem = !dstIsReg && ops[0].find('[') != std::string::npos;
    bool srcIsMem = !srcIsReg && !srcIsImm && ops[1].find('[') != std::string::npos;

    if (dstIsReg && srcIsImm) {
        std::vector<uint8_t> bytes;
        int opSize = dstSize;
        if (opSize == 8) {
            if (imm >= -0x80000000LL && imm < 0x80000000LL) {
                emitRex(bytes, 1, 0, 0, dstReg >= 8);
                bytes.push_back(0xC7);
                emitModRM(bytes, 3, 0, dstReg);
                emitImm(bytes, 4, imm);
            } else {
                if (dstReg == 0) {
                    emitRex(bytes, 1, 0, 0, 0);
                    bytes.push_back(0xB8);
                    emitImm(bytes, 8, imm);
                    return {true, bytes, "", false, {{bytes.size() - 8, static_cast<uint64_t>(imm)}}};
                } else {
                    emitRex(bytes, 1, 0, 0, dstReg >= 8);
                    bytes.push_back(0xB8 + (dstReg & 7));
                    emitImm(bytes, 8, imm);
                    return {true, bytes, "", false, {{bytes.size() - 8, static_cast<uint64_t>(imm)}}};
                }
            }
        } else if (opSize == 4) {
            emitRex(bytes, 0, 0, 0, dstReg >= 8);
            bytes.push_back(0xB8 + (dstReg & 7));
            emitImm(bytes, 4, imm);
        } else if (opSize == 2) {
            bytes.push_back(0x66);
            bytes.push_back(0xB8 + (dstReg & 7));
            emitImm(bytes, 2, imm);
        } else {
            emitRex(bytes, 0, 0, 0, dstReg >= 8);
            bytes.push_back(0xB0 + (dstReg & 7));
            emitImm(bytes, 1, imm);
        }
        return {true, bytes, "", false, {}};
    }

    if (dstIsReg && srcIsReg) {
        std::vector<uint8_t> bytes;
        int opSize = std::max(dstSize, srcSize);
        emitRex(bytes, opSize == 8, srcReg >= 8, 0, dstReg >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        bytes.push_back(opSize == 1 ? 0x88 : 0x89);
        emitModRM(bytes, 3, srcReg, dstReg);
        return {true, bytes, "", false, {}};
    }

    if (dstIsReg && srcIsMem) {
        bool ripRel = false;
        parseMemory(ops[1], base, index, scale, disp, memSize, ripRel);
        std::vector<uint8_t> bytes;
        int opSize = dstSize;
        emitRex(bytes, opSize == 8, dstReg >= 8, index >= 8, base >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        bytes.push_back(opSize == 1 ? 0x8A : 0x8B);
        if (ripRel) {
            // RIP-relative: mod=00, rm=101, disp32
            emitModRM(bytes, 0, dstReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, dstReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            bool needSib = true;
            if (base == -1) {
                emitModRM(bytes, 0, dstReg, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, dstReg, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, dstReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, dstReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, dstReg, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, dstReg, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, dstReg, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", ripRel, {}};
    }

    if (dstIsMem && srcIsReg) {
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        std::vector<uint8_t> bytes;
        int opSize = srcSize;
        emitRex(bytes, opSize == 8, srcReg >= 8, index >= 8, base >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        bytes.push_back(opSize == 1 ? 0x88 : 0x89);
        if (ripRel) {
            emitModRM(bytes, 0, srcReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, srcReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, srcReg, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, srcReg, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, srcReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, srcReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, srcReg, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, srcReg, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, srcReg, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", ripRel, {}};
    }

    if (dstIsMem && srcIsImm) {
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        std::vector<uint8_t> bytes;
        emitRex(bytes, memSize == 8, 0, index >= 8, base >= 8);
        if (memSize == 2) bytes.push_back(0x66);
        bytes.push_back(0xC7);
        if (ripRel) {
            emitModRM(bytes, 0, 0, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, 0, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, 0, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, 0, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, 0, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, 0, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, 0, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, 0, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, 0, base);
            emitDisp(bytes, 4, disp);
        }
        int immSz = (memSize <= 1) ? 1 : (memSize <= 2) ? 2 : 4;
        emitImm(bytes, immSz, imm);
        return {true, bytes, "", ripRel, {}};
    }

    return {false, {}, "MOV: unsupported operand combination", false, {}};
}

AsmResult Assembler::asmLea(const std::vector<std::string>& ops, uint64_t address) const {
    if (ops.size() != 2) return {false, {}, "LEA: expected 2 operands", false, {}};
    int dstReg, dstSize;
    if (!parseRegister(ops[0], dstReg, dstSize))
        return {false, {}, "LEA: invalid destination register", false, {}};
    int base, index, scale, memSize;
    int64_t disp;
    bool ripRel = false;
    if (!parseMemory(ops[1], base, index, scale, disp, memSize, ripRel))
        return {false, {}, "LEA: invalid memory operand", false, {}};

    std::vector<uint8_t> bytes;
    emitRex(bytes, 1, 0, index >= 8, base >= 8);
    bytes.push_back(0x8D);
    if (ripRel) {
        emitModRM(bytes, 0, dstReg, 5);
        emitDisp(bytes, 4, disp);
    } else if (base == -1 && index == -1) {
        emitModRM(bytes, 0, dstReg, 5);
        emitDisp(bytes, 4, disp);
    } else if (index != -1) {
        if (base == -1) {
            emitModRM(bytes, 0, dstReg, 4);
            emitSib(bytes, scale, index, 5);
            emitDisp(bytes, 4, 0);
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, dstReg, 4);
            emitSib(bytes, scale, index, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, dstReg, 4);
            emitSib(bytes, scale, index, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, dstReg, 4);
            emitSib(bytes, scale, index, base);
            emitDisp(bytes, 4, disp);
        }
    } else if (disp == 0 && (base & 7) != 5) {
        emitModRM(bytes, 0, dstReg, base);
    } else if (disp >= -128 && disp < 128) {
        emitModRM(bytes, 1, dstReg, base);
        emitDisp(bytes, 1, disp);
    } else {
        emitModRM(bytes, 2, dstReg, base);
        emitDisp(bytes, 4, disp);
    }
    return {true, bytes, "", ripRel, {}};
}

AsmResult Assembler::asmXor(const std::vector<std::string>& ops) const {
    if (ops.size() != 2) return {false, {}, "XOR: expected 2 operands", false, {}};
    int dstReg, dstSize, srcReg, srcSize;
    if (parseRegister(ops[0], dstReg, dstSize) && parseRegister(ops[1], srcReg, srcSize)) {
        if (dstReg == srcReg) {
            std::vector<uint8_t> bytes;
            emitRex(bytes, dstSize == 8, 0, 0, dstReg >= 8);
            bytes.push_back(0x31);
            emitModRM(bytes, 3, srcReg, dstReg);
            return {true, bytes, "", false, {}};
        }
    }
    return asmArith("XOR", ops);
}

AsmResult Assembler::asmTest(const std::vector<std::string>& ops) const {
    return asmArith("TEST", ops);
}

AsmResult Assembler::asmArith(const std::string& mnem, const std::vector<std::string>& ops) const {
    if (ops.size() != 2) return {false, {}, mnem + ": expected 2 operands", false, {}};
    int dstReg, dstSize, srcReg, srcSize;
    int64_t imm;
    bool dstIsReg = parseRegister(ops[0], dstReg, dstSize);
    bool srcIsReg = parseRegister(ops[1], srcReg, srcSize);
    bool srcIsImm = !srcIsReg && parseImmediate(ops[1], imm);

    static const std::unordered_map<std::string, std::pair<int, int>> opMap = {
        {"ADD", {0, 0}}, {"OR", {1, 1}}, {"AND", {4, 4}},
        {"SUB", {5, 5}}, {"XOR", {6, 6}}, {"CMP", {7, 7}},
        {"TEST", {0, 0}}
    };

    auto it = opMap.find(mnem);
    if (it == opMap.end()) return {false, {}, "unknown arithmetic: " + mnem, false, {}};
    int opcode_low = it->second.first;
    int opcode_high = it->second.second;

    if (dstIsReg && srcIsImm) {
        std::vector<uint8_t> bytes;
        int opSize = dstSize;
        if (opSize == 1 && imm >= -128 && imm < 128) {
            emitRex(bytes, 0, 0, 0, dstReg >= 8);
            bytes.push_back(0x80 + opcode_low);
            emitModRM(bytes, 3, opcode_high, dstReg);
            emitImm(bytes, 1, imm);
        } else if (imm >= -128 && imm < 128) {
            emitRex(bytes, opSize == 8, 0, 0, dstReg >= 8);
            if (opSize == 2) bytes.push_back(0x66);
            bytes.push_back(0x83);
            emitModRM(bytes, 3, opcode_high, dstReg);
            emitImm(bytes, 1, imm);
        } else {
            int immSz = (opSize <= 2) ? 2 : 4;
            emitRex(bytes, opSize == 8, 0, 0, dstReg >= 8);
            if (opSize == 2) bytes.push_back(0x66);
            bytes.push_back(mnem == "TEST" ? 0xF7 : (0x81));
            emitModRM(bytes, 3, opcode_high, dstReg);
            emitImm(bytes, immSz, imm);
        }
        return {true, bytes, "", false, {}};
    }

    if (dstIsReg && srcIsReg) {
        std::vector<uint8_t> bytes;
        int opSize = std::max(dstSize, srcSize);
        emitRex(bytes, opSize == 8, srcReg >= 8, 0, dstReg >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        if (mnem == "TEST") {
            bytes.push_back(opSize == 1 ? 0x84 : 0x85);
        } else {
            bytes.push_back(opSize == 1 ? (0x00 + opcode_low) : (0x01 + opcode_low));
        }
        emitModRM(bytes, 3, srcReg, dstReg);
        return {true, bytes, "", false, {}};
    }

    bool dstIsMem = !dstIsReg && ops[0].find('[') != std::string::npos;
    bool srcIsMem = !srcIsReg && !srcIsImm && ops[1].find('[') != std::string::npos;

    if (dstIsReg && srcIsMem) {
        std::vector<uint8_t> bytes;
        int opSize = dstSize;
        int base, index, scale, memSize;
        int64_t disp;
        bool ripRel = false;
        parseMemory(ops[1], base, index, scale, disp, memSize, ripRel);
        emitRex(bytes, opSize == 8, dstReg >= 8, index >= 8, base >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        if (mnem == "TEST") {
            bytes.push_back(opSize == 1 ? 0x84 : 0x85);
        } else {
            bytes.push_back(opSize == 1 ? (0x00 + opcode_low) : (0x01 + opcode_low));
        }
        if (ripRel) {
            emitModRM(bytes, 0, dstReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, dstReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, dstReg, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, dstReg, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, dstReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, dstReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, dstReg, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, dstReg, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, dstReg, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", false, {}};
    }

    if (dstIsMem && srcIsReg) {
        std::vector<uint8_t> bytes;
        int opSize = srcSize;
        int base, index, scale, memSize;
        int64_t disp;
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        emitRex(bytes, opSize == 8, srcReg >= 8, index >= 8, base >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        bytes.push_back(opSize == 1 ? (0x00 + opcode_low) : (0x01 + opcode_low));
        if (ripRel) {
            emitModRM(bytes, 0, srcReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, srcReg, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, srcReg, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, srcReg, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, srcReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, srcReg, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, srcReg, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, srcReg, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, srcReg, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", false, {}};
    }

    if (dstIsMem && srcIsImm) {
        std::vector<uint8_t> bytes;
        int base, index, scale, memSize;
        int64_t disp;
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        int opSize = memSize;
        emitRex(bytes, opSize == 8, 0, index >= 8, base >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        if (opSize == 1 && imm >= -128 && imm < 128) {
            bytes.push_back(0x80 + opcode_low);
        } else if (imm >= -128 && imm < 128) {
            bytes.push_back(0x83);
        } else {
            bytes.push_back(mnem == "TEST" ? 0xF7 : 0x81);
        }
        if (ripRel) {
            emitModRM(bytes, 0, opcode_high, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, opcode_high, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, opcode_high, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, opcode_high, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, opcode_high, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, opcode_high, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, opcode_high, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, opcode_high, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, opcode_high, base);
            emitDisp(bytes, 4, disp);
        }
        int immSz;
        if (opSize == 1 || (imm >= -128 && imm < 128)) immSz = 1;
        else if (opSize <= 2) immSz = 2;
        else immSz = 4;
        emitImm(bytes, immSz, imm);
        return {true, bytes, "", false, {}};
    }

    return {false, {}, mnem + ": unsupported operand combination", false, {}};
}

AsmResult Assembler::asmIncDec(const std::string& mnem, const std::vector<std::string>& ops) const {
    if (ops.size() != 1) return {false, {}, mnem + ": expected 1 operand", false, {}};
    int reg, size;
    if (!parseRegister(ops[0], reg, size))
        return {false, {}, mnem + ": invalid register", false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, size == 8, 0, 0, reg >= 8);
    bytes.push_back(0xFF);
    emitModRM(bytes, 3, (mnem == "INC") ? 0 : 1, reg);
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmJmp(const std::vector<std::string>& ops, uint64_t address) const {
    if (ops.empty()) return {false, {}, "JMP: missing operand", false, {}};
    int64_t target;
    if (parseImmediate(ops[0], target)) {
        int64_t rel = target - static_cast<int64_t>(address) - 2;
        if (rel >= -128 && rel < 128) {
            return {true, {0xEB, static_cast<uint8_t>(rel & 0xFF)}, ""};
        }
        rel = target - static_cast<int64_t>(address) - 5;
        if (rel < -2147483648LL || rel > 2147483647LL)
            return {false, {}, "JMP: target out of range for near jump", false, {}};
        std::vector<uint8_t> bytes = {0xE9};
        emitImm(bytes, 4, rel);
        return {true, bytes, "", false, {}};
    }
    int reg, size;
    if (parseRegister(ops[0], reg, size)) {
        std::vector<uint8_t> bytes;
        emitRex(bytes, 0, 0, 0, reg >= 8);
        bytes.push_back(0xFF);
        emitModRM(bytes, 3, 4, reg);
        return {true, bytes, "", false, {}};
    }
    if (ops[0].find('[') != std::string::npos) {
        int base, index, scale, memSize;
        int64_t disp;
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        std::vector<uint8_t> bytes;
        emitRex(bytes, 0, 0, index >= 8, base >= 8);
        bytes.push_back(0xFF);
        if (ripRel) {
            emitModRM(bytes, 0, 4, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, 4, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, 4, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, 4, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, 4, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, 4, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, 4, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, 4, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, 4, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", ripRel, {}};
    }
    return {false, {}, "JMP: unsupported operand", false, {}};
}

AsmResult Assembler::asmCall(const std::vector<std::string>& ops, uint64_t address) const {
    if (ops.empty()) return {false, {}, "CALL: missing operand", false, {}};
    int64_t target;
    if (parseImmediate(ops[0], target)) {
        int64_t rel = target - static_cast<int64_t>(address) - 5;
        if (rel < -2147483648LL || rel > 2147483647LL)
            return {false, {}, "CALL: target out of range", false, {}};
        std::vector<uint8_t> bytes = {0xE8};
        emitImm(bytes, 4, rel);
        return {true, bytes, "", false, {}};
    }
    int reg, size;
    if (parseRegister(ops[0], reg, size)) {
        std::vector<uint8_t> bytes;
        emitRex(bytes, 0, 0, 0, reg >= 8);
        bytes.push_back(0xFF);
        emitModRM(bytes, 3, 2, reg);
        return {true, bytes, "", false, {}};
    }
    if (ops[0].find('[') != std::string::npos) {
        int base, index, scale, memSize;
        int64_t disp;
        bool ripRel = false;
        parseMemory(ops[0], base, index, scale, disp, memSize, ripRel);
        std::vector<uint8_t> bytes;
        emitRex(bytes, 0, 0, index >= 8, base >= 8);
        bytes.push_back(0xFF);
        if (ripRel) {
            emitModRM(bytes, 0, 2, 5);
            emitDisp(bytes, 4, disp);
        } else if (base == -1 && index == -1) {
            emitModRM(bytes, 0, 2, 5);
            emitDisp(bytes, 4, disp);
        } else if (index != -1) {
            if (base == -1) {
                emitModRM(bytes, 0, 2, 4);
                emitSib(bytes, scale, index, 5);
                emitDisp(bytes, 4, 0);
            } else if (disp == 0 && (base & 7) != 5) {
                emitModRM(bytes, 0, 2, 4);
                emitSib(bytes, scale, index, base);
            } else if (disp >= -128 && disp < 128) {
                emitModRM(bytes, 1, 2, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 1, disp);
            } else {
                emitModRM(bytes, 2, 2, 4);
                emitSib(bytes, scale, index, base);
                emitDisp(bytes, 4, disp);
            }
        } else if (disp == 0 && (base & 7) != 5) {
            emitModRM(bytes, 0, 2, base);
        } else if (disp >= -128 && disp < 128) {
            emitModRM(bytes, 1, 2, base);
            emitDisp(bytes, 1, disp);
        } else {
            emitModRM(bytes, 2, 2, base);
            emitDisp(bytes, 4, disp);
        }
        return {true, bytes, "", ripRel, {}};
    }
    return {false, {}, "CALL: unsupported operand", false, {}};
}

AsmResult Assembler::asmJcc(const std::string& mnem, const std::vector<std::string>& ops, uint64_t address) const {
    if (ops.empty()) return {false, {}, mnem + ": missing operand", false, {}};
    int64_t target;
    if (!parseImmediate(ops[0], target))
        return {false, {}, mnem + ": only direct addressing supported", false, {}};

    static const std::unordered_map<std::string, uint8_t> jccMap = {
        {"JO", 0x70}, {"JNO", 0x71}, {"JB", 0x72}, {"JNB", 0x73},
        {"JZ", 0x74}, {"JNZ", 0x75}, {"JBE", 0x76}, {"JNBE", 0x77},
        {"JS", 0x78}, {"JNS", 0x79}, {"JP", 0x7A}, {"JNP", 0x7B},
        {"JL", 0x7C}, {"JNL", 0x7D}, {"JLE", 0x7E}, {"JNLE", 0x7F},
        {"JE", 0x74}, {"JNE", 0x75}, {"JA", 0x77}, {"JAE", 0x73},
        {"JG", 0x7F}, {"JGE", 0x7D}, {"JNGE", 0x7C}, {"JNG", 0x7E},
        {"JNAE", 0x72}, {"JC", 0x72}, {"JNC", 0x73}, {"JNA", 0x76},
    };
    auto it = jccMap.find(mnem);
    if (it == jccMap.end()) return {false, {}, "unknown Jcc: " + mnem, false, {}};
    uint8_t shortOpcode = it->second;
    int64_t rel = target - static_cast<int64_t>(address) - 2;
    if (rel >= -128 && rel < 128) {
        return {true, {shortOpcode, static_cast<uint8_t>(rel & 0xFF)}, ""};
    }
    rel = target - static_cast<int64_t>(address) - 6;
    if (rel < -2147483648LL || rel > 2147483647LL)
        return {false, {}, mnem + ": target out of range", false, {}};
    std::vector<uint8_t> bytes = {0x0F, static_cast<uint8_t>(shortOpcode + 0x10)};
    emitImm(bytes, 4, rel);
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmMovzx(const std::vector<std::string>& ops) const {
    if (ops.size() != 2) return {false, {}, "MOVZX: expected 2 operands", false, {}};
    int dstReg, dstSize, srcReg, srcSize;
    if (!parseRegister(ops[0], dstReg, dstSize) || !parseRegister(ops[1], srcReg, srcSize))
        return {false, {}, "MOVZX: invalid registers", false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, dstSize == 8, srcReg >= 8, 0, dstReg >= 8);
    if (srcSize == 1) bytes.push_back(0x0F);
    bytes.push_back(srcSize == 1 ? 0xB6 : 0xB7);
    emitModRM(bytes, 3, srcReg, dstReg);
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmMovsx(const std::vector<std::string>& ops) const {
    if (ops.size() != 2) return {false, {}, "MOVSX: expected 2 operands", false, {}};
    int dstReg, dstSize, srcReg, srcSize;
    if (!parseRegister(ops[0], dstReg, dstSize) || !parseRegister(ops[1], srcReg, srcSize))
        return {false, {}, "MOVSX: invalid registers", false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, dstSize == 8, srcReg >= 8, 0, dstReg >= 8);
    if (srcSize == 1) bytes.push_back(0x0F);
    bytes.push_back(srcSize == 1 ? 0xBE : 0xBF);
    emitModRM(bytes, 3, srcReg, dstReg);
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmImul(const std::vector<std::string>& ops) const {
    if (ops.size() == 2) {
        int dstReg, dstSize, srcReg, srcSize;
        if (!parseRegister(ops[0], dstReg, dstSize) || !parseRegister(ops[1], srcReg, srcSize))
            return {false, {}, "IMUL: invalid registers", false, {}};
        std::vector<uint8_t> bytes;
        emitRex(bytes, dstSize == 8, srcReg >= 8, 0, dstReg >= 8);
        if (dstSize == 2) bytes.push_back(0x66);
        bytes.push_back(0x0F);
        bytes.push_back(0xAF);
        emitModRM(bytes, 3, dstReg, srcReg);
        return {true, bytes, "", false, {}};
    }
    if (ops.size() == 3) {
        int dstReg, dstSize, srcReg, srcSize;
        int64_t imm;
        if (!parseRegister(ops[0], dstReg, dstSize) ||
            !parseRegister(ops[1], srcReg, srcSize) ||
            !parseImmediate(ops[2], imm))
            return {false, {}, "IMUL: invalid operands", false, {}};
        std::vector<uint8_t> bytes;
        int opSize = std::max(dstSize, srcSize);
        emitRex(bytes, opSize == 8, srcReg >= 8, 0, dstReg >= 8);
        if (opSize == 2) bytes.push_back(0x66);
        if (imm >= -128 && imm < 128) {
            bytes.push_back(0x6B);
            emitModRM(bytes, 3, dstReg, srcReg);
            emitImm(bytes, 1, imm);
        } else {
            bytes.push_back(0x69);
            emitModRM(bytes, 3, dstReg, srcReg);
            emitImm(bytes, (opSize <= 2) ? 2 : 4, imm);
        }
        return {true, bytes, "", false, {}};
    }
    return {false, {}, "IMUL: expected 2 or 3 operands", false, {}};
}

AsmResult Assembler::asmXchg(const std::vector<std::string>& ops) const {
    if (ops.size() != 2) return {false, {}, "XCHG: expected 2 operands", false, {}};
    int reg1, size1, reg2, size2;
    if (!parseRegister(ops[0], reg1, size1) || !parseRegister(ops[1], reg2, size2))
        return {false, {}, "XCHG: invalid registers", false, {}};
    if (size1 != size2) return {false, {}, "XCHG: operand size mismatch", false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, size1 == 8, reg1 >= 8, 0, reg2 >= 8);
    if (size1 == 2) bytes.push_back(0x66);
    bytes.push_back(size1 == 1 ? 0x86 : 0x87);
    emitModRM(bytes, 3, reg1, reg2);
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmBswap(const std::vector<std::string>& ops) const {
    if (ops.size() != 1) return {false, {}, "BSWAP: expected 1 operand", false, {}};
    int reg, size;
    if (!parseRegister(ops[0], reg, size))
        return {false, {}, "BSWAP: invalid register", false, {}};
    if (size != 4 && size != 8)
        return {false, {}, "BSWAP: register must be 32-bit or 64-bit", false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, size == 8, 0, 0, reg >= 8);
    bytes.push_back(0x0F);
    bytes.push_back(0xC8 + (reg & 7));
    return {true, bytes, "", false, {}};
}

AsmResult Assembler::asmSetcc(const std::string& mnem, const std::vector<std::string>& ops) const {
    if (ops.size() != 1) return {false, {}, mnem + ": expected 1 operand", false, {}};
    int reg, size;
    if (!parseRegister(ops[0], reg, size))
        return {false, {}, mnem + ": invalid register", false, {}};

    static const std::unordered_map<std::string, uint8_t> setccMap = {
        {"SETO", 0x90}, {"SETNO", 0x91}, {"SETB", 0x92}, {"SETNB", 0x93},
        {"SETZ", 0x94}, {"SETNZ", 0x95}, {"SETBE", 0x96}, {"SETNBE", 0x97},
        {"SETS", 0x98}, {"SETNS", 0x99}, {"SETP", 0x9A}, {"SETNP", 0x9B},
        {"SETL", 0x9C}, {"SETNL", 0x9D}, {"SETLE", 0x9E}, {"SETNLE", 0x9F},
        {"SETE", 0x94}, {"SETNE", 0x95}, {"SETA", 0x97}, {"SETAE", 0x93},
        {"SETG", 0x9F}, {"SETGE", 0x9D}, {"SETLE", 0x9E}, {"SETNG", 0x9E},
        {"SETC", 0x92}, {"SETNC", 0x93},
    };
    auto it = setccMap.find(mnem);
    if (it == setccMap.end()) return {false, {}, "unknown SETcc: " + mnem, false, {}};
    std::vector<uint8_t> bytes;
    emitRex(bytes, 0, 0, 0, reg >= 8);
    bytes.push_back(0x0F);
    bytes.push_back(it->second);
    emitModRM(bytes, 3, 0, reg);
    return {true, bytes, "", false, {}};
}

} // namespace ghidra
