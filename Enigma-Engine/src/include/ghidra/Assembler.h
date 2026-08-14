#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace ghidra {

struct AsmResult {
    bool success = false;
    std::vector<uint8_t> bytes;
    std::string error;
    bool ripRelative = false;
    struct AbsoluteRef {
        size_t offset;
        uint64_t value;
    };
    std::vector<AbsoluteRef> absoluteRefs;
};

class Assembler {
public:
    Assembler();

    AsmResult assemble(const std::string& text, uint64_t address = 0);

    static Assembler& instance();

    // Intel-recommended multi-byte NOP encodings for sizes 1-9.
    // For sizes > 9, emits a 9-byte NOP + recurses.
    static std::vector<uint8_t> generateMultiByteNop(size_t size);
    static void fillMultiByteNopGap(std::vector<uint8_t>& out, size_t gapSize);

    // Ghidra-style suggestion list: given the current typed text (first token
    // treated as mnemonic), returns all mnemonics in the same instruction
    // family (e.g. "jz" -> all Jcc variants, "mov" -> MOV/MOVZX/MOVSX/LEA/XCHG).
    static std::vector<std::string> getSuggestions(const std::string& input);

private:
    struct Token {
        std::string mnemonic;
        std::string operands;
    };

    Token tokenize(const std::string& text) const;
    std::vector<std::string> splitOperands(const std::string& ops) const;
    std::string toUpper(std::string s) const;
    std::string trim(const std::string& s) const;

    bool parseRegister(const std::string& s, int& reg, int& size) const;
    bool parseMemory(const std::string& s, int& base, int& index, int& scale, int64_t& disp, int& size, bool& ripRelative) const;
    bool parseImmediate(const std::string& s, int64_t& val) const;

    void emitRex(std::vector<uint8_t>& out, int w, int r, int x, int b) const;
    void emitModRM(std::vector<uint8_t>& out, int mod, int reg, int rm) const;
    void emitSib(std::vector<uint8_t>& out, int scale, int index, int rm) const;
    void emitDisp(std::vector<uint8_t>& out, int size, int64_t disp) const;
    void emitImm(std::vector<uint8_t>& out, int size, int64_t val) const;

    AsmResult assembleOne(const std::string& mnemonic, const std::vector<std::string>& operands, uint64_t address) const;

    AsmResult asmNop(const std::vector<std::string>& ops) const;
    AsmResult asmRet(const std::vector<std::string>& ops) const;
    AsmResult asmInt3(const std::vector<std::string>& ops) const;
    AsmResult asmPushPop(const std::string& mnem, const std::vector<std::string>& ops) const;
    AsmResult asmMov(const std::vector<std::string>& ops, uint64_t address) const;
    AsmResult asmLea(const std::vector<std::string>& ops, uint64_t address) const;
    AsmResult asmXor(const std::vector<std::string>& ops) const;
    AsmResult asmTest(const std::vector<std::string>& ops) const;
    AsmResult asmArith(const std::string& mnem, const std::vector<std::string>& ops) const;
    AsmResult asmIncDec(const std::string& mnem, const std::vector<std::string>& ops) const;
    AsmResult asmJmp(const std::vector<std::string>& ops, uint64_t address) const;
    AsmResult asmCall(const std::vector<std::string>& ops, uint64_t address) const;
    AsmResult asmJcc(const std::string& mnem, const std::vector<std::string>& ops, uint64_t address) const;
    AsmResult asmMovzx(const std::vector<std::string>& ops) const;
    AsmResult asmMovsx(const std::vector<std::string>& ops) const;
    AsmResult asmImul(const std::vector<std::string>& ops) const;
    AsmResult asmXchg(const std::vector<std::string>& ops) const;
    AsmResult asmBswap(const std::vector<std::string>& ops) const;
    AsmResult asmSetcc(const std::string& mnem, const std::vector<std::string>& ops) const;

    static const std::unordered_map<std::string, int> regMap_;
};

} // namespace ghidra
