#pragma once

#include <ghidra/SequenceNumber.h>
#include <ghidra/Varnode.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>

namespace ghidra {

class PcodeOp {
public:
    static constexpr int UNIMPLEMENTED = 0;
    static constexpr int COPY = 1;
    static constexpr int LOAD = 2;
    static constexpr int STORE = 3;
    static constexpr int BRANCH = 4;
    static constexpr int CBRANCH = 5;
    static constexpr int BRANCHIND = 6;
    static constexpr int CALL = 7;
    static constexpr int CALLIND = 8;
    static constexpr int CALLOTHER = 9;
    static constexpr int RETURN = 10;
    static constexpr int INT_EQUAL = 11;
    static constexpr int INT_NOTEQUAL = 12;
    static constexpr int INT_SLESS = 13;
    static constexpr int INT_SLESSEQUAL = 14;
    static constexpr int INT_LESS = 15;
    static constexpr int INT_LESSEQUAL = 16;
    static constexpr int INT_ZEXT = 17;
    static constexpr int INT_SEXT = 18;
    static constexpr int INT_ADD = 19;
    static constexpr int INT_SUB = 20;
    static constexpr int INT_CARRY = 21;
    static constexpr int INT_SCARRY = 22;
    static constexpr int INT_SBORROW = 23;
    static constexpr int INT_2COMP = 24;
    static constexpr int INT_NEGATE = 25;
    static constexpr int INT_XOR = 26;
    static constexpr int INT_AND = 27;
    static constexpr int INT_OR = 28;
    static constexpr int INT_LEFT = 29;
    static constexpr int INT_RIGHT = 30;
    static constexpr int INT_SRIGHT = 31;
    static constexpr int INT_MULT = 32;
    static constexpr int INT_DIV = 33;
    static constexpr int INT_SDIV = 34;
    static constexpr int INT_REM = 35;
    static constexpr int INT_SREM = 36;
    static constexpr int BOOL_NEGATE = 37;
    static constexpr int BOOL_XOR = 38;
    static constexpr int BOOL_AND = 39;
    static constexpr int BOOL_OR = 40;
    static constexpr int FLOAT_EQUAL = 41;
    static constexpr int FLOAT_NOTEQUAL = 42;
    static constexpr int FLOAT_LESS = 43;
    static constexpr int FLOAT_LESSEQUAL = 44;
    static constexpr int FLOAT_NAN = 46;
    static constexpr int FLOAT_ADD = 47;
    static constexpr int FLOAT_DIV = 48;
    static constexpr int FLOAT_MULT = 49;
    static constexpr int FLOAT_SUB = 50;
    static constexpr int FLOAT_NEG = 51;
    static constexpr int FLOAT_ABS = 52;
    static constexpr int FLOAT_SQRT = 53;
    static constexpr int FLOAT_INT2FLOAT = 54;
    static constexpr int FLOAT_FLOAT2FLOAT = 55;
    static constexpr int FLOAT_TRUNC = 56;
    static constexpr int FLOAT_CEIL = 57;
    static constexpr int FLOAT_FLOOR = 58;
    static constexpr int FLOAT_ROUND = 59;
    static constexpr int MULTIEQUAL = 60;
    static constexpr int INDIRECT = 61;
    static constexpr int PIECE = 62;
    static constexpr int SUBPIECE = 63;
    static constexpr int CAST = 64;
    static constexpr int PTRADD = 65;
    static constexpr int PTRSUB = 66;
    static constexpr int SEGMENTOP = 67;
    static constexpr int CPOOLREF = 68;
    static constexpr int NEW = 69;
    static constexpr int INSERT = 70;
    static constexpr int ZPULL = 71;
    static constexpr int POPCOUNT = 72;
    static constexpr int LZCOUNT = 73;
    static constexpr int SPULL = 74;
    static constexpr int PCODE_MAX = 75;

    PcodeOp(SequenceNumber sq, int op, int numInputs, Varnode* out);
    PcodeOp(SequenceNumber sq, int op, const std::vector<Varnode*>& in, Varnode* out);
    PcodeOp(Address a, int seqNum, int op, const std::vector<Varnode*>& in, Varnode* out);
    PcodeOp(Address a, int seqNum, int op, const std::vector<Varnode*>& in);
    PcodeOp(Address a, int seqNum, int op);
    virtual ~PcodeOp() = default;

    int getOpcode() const { return opcode; }
    int getNumInputs() const { return static_cast<int>(input.size()); }
    const std::vector<Varnode*>& getInputs() const { return input; }
    Varnode* getInput(int i) const {
        if (i < 0 || i >= static_cast<int>(input.size())) return nullptr;
        return input[i];
    }
    Varnode* getOutput() const { return output; }

    int getSlot(Varnode* vn) const;

    std::string getMnemonic() const {
        return getMnemonic(opcode);
    }

    bool isDead() const { return false; }
    bool isAssignment() const { return output != nullptr; }
    bool isCommutative() const { return isCommutative(opcode); }
    const SequenceNumber& getSeqnum() const { return seqnum; }

    void setOpcode(int o) { opcode = o; }
    void setInput(Varnode* vn, int slot);
    void removeInput(int slot);
    void insertInput(Varnode* vn, int slot);
    void setTime(int t) { seqnum.setTime(t); }
    void setOrder(int ord) { seqnum.setOrder(ord); }
    void setOutput(Varnode* vn) { output = vn; }

    static std::string getMnemonic(int op);
    static int getOpcode(const std::string& s);
    static bool isCommutative(int op);

    std::string toString() const;

private:
    int opcode;
    SequenceNumber seqnum;
    std::vector<Varnode*> input;
    Varnode* output;
};

} // namespace ghidra
