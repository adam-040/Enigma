/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeOp.cpp
/// \brief PcodeOp implementation - pcode operation
#include "ghidra/PcodeOp.h"

namespace ghidra {

PcodeOp::PcodeOp(SequenceNumber sq, int op, int numInputs, Varnode* out)
    : opcode(op), seqnum(sq), output(out) {
    input.resize(numInputs, nullptr);
}

PcodeOp::PcodeOp(SequenceNumber sq, int op, const std::vector<Varnode*>& in, Varnode* out)
    : opcode(op), seqnum(sq), input(in), output(out) {}

PcodeOp::PcodeOp(Address a, int seqNum, int op, const std::vector<Varnode*>& in, Varnode* out)
    : opcode(op), seqnum(SequenceNumber(a, seqNum)), input(in), output(out) {}

PcodeOp::PcodeOp(Address a, int seqNum, int op, const std::vector<Varnode*>& in)
    : PcodeOp(a, seqNum, op, in, nullptr) {}

PcodeOp::PcodeOp(Address a, int seqNum, int op)
    : PcodeOp(a, seqNum, op, std::vector<Varnode*>(), nullptr) {}

int PcodeOp::getSlot(Varnode* vn) const {
    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == vn) return static_cast<int>(i);
    }
    return -1;
}

void PcodeOp::setInput(Varnode* vn, int slot) {
    if (slot >= static_cast<int>(input.size())) {
        input.resize(slot + 1, nullptr);
    }
    input[slot] = vn;
}

void PcodeOp::removeInput(int slot) {
    if (slot >= 0 && slot < static_cast<int>(input.size())) {
        input.erase(input.begin() + slot);
    }
}

void PcodeOp::insertInput(Varnode* vn, int slot) {
    if (slot < 0) slot = 0;
    if (slot > static_cast<int>(input.size())) slot = input.size();
    input.insert(input.begin() + slot, vn);
}

std::string PcodeOp::getMnemonic(int op) {
    static const char* names[] = {
        "UNIMPLEMENTED", "COPY", "LOAD", "STORE", "BRANCH", "CBRANCH",
        "BRANCHIND", "CALL", "CALLIND", "CALLOTHER", "RETURN",
        "INT_EQUAL", "INT_NOTEQUAL", "INT_SLESS", "INT_SLESSEQUAL",
        "INT_LESS", "INT_LESSEQUAL", "INT_ZEXT", "INT_SEXT",
        "INT_ADD", "INT_SUB", "INT_CARRY", "INT_SCARRY", "INT_SBORROW",
        "INT_2COMP", "INT_NEGATE", "INT_XOR", "INT_AND", "INT_OR",
        "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_MULT", "INT_DIV",
        "INT_SDIV", "INT_REM", "INT_SREM", "BOOL_NEGATE", "BOOL_XOR",
        "BOOL_AND", "BOOL_OR", "FLOAT_EQUAL", "FLOAT_NOTEQUAL",
        "FLOAT_LESS", "FLOAT_LESSEQUAL", "UNKNOWN_45", "FLOAT_NAN",
        "FLOAT_ADD", "FLOAT_DIV", "FLOAT_MULT", "FLOAT_SUB",
        "FLOAT_NEG", "FLOAT_ABS", "FLOAT_SQRT", "FLOAT_INT2FLOAT",
        "FLOAT_FLOAT2FLOAT", "FLOAT_TRUNC", "FLOAT_CEIL", "FLOAT_FLOOR",
        "FLOAT_ROUND", "BUILD", "DELAY_SLOT", "PIECE", "SUBPIECE",
        "CAST", "PTRADD", "PTRSUB", "SEGMENTOP", "CPOOLREF",
        "NEW", "INSERT", "ZPULL", "POPCOUNT", "LZCOUNT", "SPULL"
    };
    if (op >= 0 && op < PCODE_MAX) return names[op];
    return "UNKNOWN";
}

int PcodeOp::getOpcode(const std::string& s) {
    static const std::unordered_map<std::string, int> lookup = {
        {"COPY", 1}, {"LOAD", 2}, {"STORE", 3}, {"BRANCH", 4}, {"CBRANCH", 5},
        {"BRANCHIND", 6}, {"CALL", 7}, {"CALLIND", 8}, {"CALLOTHER", 9}, {"RETURN", 10},
        {"INT_EQUAL", 11}, {"INT_NOTEQUAL", 12}, {"INT_SLESS", 13}, {"INT_SLESSEQUAL", 14},
        {"INT_LESS", 15}, {"INT_LESSEQUAL", 16}, {"INT_ZEXT", 17}, {"INT_SEXT", 18},
        {"INT_ADD", 19}, {"INT_SUB", 20}, {"INT_CARRY", 21}, {"INT_SCARRY", 22},
        {"INT_SBORROW", 23}, {"INT_2COMP", 24}, {"INT_NEGATE", 25}, {"INT_XOR", 26},
        {"INT_AND", 27}, {"INT_OR", 28}, {"INT_LEFT", 29}, {"INT_RIGHT", 30},
        {"INT_SRIGHT", 31}, {"INT_MULT", 32}, {"INT_DIV", 33}, {"INT_SDIV", 34},
        {"INT_REM", 35}, {"INT_SREM", 36}, {"BOOL_NEGATE", 37}, {"BOOL_XOR", 38},
        {"BOOL_AND", 39}, {"BOOL_OR", 40}, {"FLOAT_EQUAL", 41}, {"FLOAT_NOTEQUAL", 42},
        {"FLOAT_LESS", 43}, {"FLOAT_LESSEQUAL", 44}, {"FLOAT_NAN", 46},
        {"FLOAT_ADD", 47}, {"FLOAT_DIV", 48}, {"FLOAT_MULT", 49}, {"FLOAT_SUB", 50},
        {"FLOAT_NEG", 51}, {"FLOAT_ABS", 52}, {"FLOAT_SQRT", 53}, {"FLOAT_INT2FLOAT", 54},
        {"FLOAT_FLOAT2FLOAT", 55}, {"FLOAT_TRUNC", 56}, {"FLOAT_CEIL", 57},
        {"FLOAT_FLOOR", 58}, {"FLOAT_ROUND", 59}, {"BUILD", 60}, {"DELAY_SLOT", 61},
        {"PIECE", 62}, {"SUBPIECE", 63}, {"CAST", 64}, {"PTRADD", 65}, {"PTRSUB", 66},
        {"SEGMENTOP", 67}, {"CPOOLREF", 68}, {"NEW", 69}, {"INSERT", 70},
        {"ZPULL", 71}, {"POPCOUNT", 72}, {"LZCOUNT", 73}, {"SPULL", 74}
    };
    auto it = lookup.find(s);
    return (it != lookup.end()) ? it->second : PCODE_MAX;
}

bool PcodeOp::isCommutative(int op) {
    return op == INT_ADD || op == INT_MULT || op == INT_XOR || op == INT_AND ||
           op == INT_OR || op == INT_EQUAL || op == INT_NOTEQUAL ||
           op == BOOL_XOR || op == BOOL_AND || op == BOOL_OR ||
           op == FLOAT_ADD || op == FLOAT_MULT || op == FLOAT_EQUAL || op == FLOAT_NOTEQUAL;
}

std::string PcodeOp::toString() const {
    std::stringstream ss;
    if (output) ss << output->toString();
    else ss << " --- ";
    ss << " " << getMnemonic() << " ";
    for (size_t i = 0; i < input.size(); ++i) {
        if (!input[i]) ss << "null";
        else ss << input[i]->toString();
        if (i < input.size() - 1) ss << " , ";
    }
    return ss.str();
}

} // namespace ghidra
