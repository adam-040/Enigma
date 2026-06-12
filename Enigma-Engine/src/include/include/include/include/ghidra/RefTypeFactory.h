/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file RefTypeFactory.h
/// \brief Factory class to create RefType objects
/// Translated from: ghidra.program.model.symbol.RefTypeFactory
#pragma once

#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <ghidra/Reference.h>
#include <cstdint>
#include <vector>

namespace ghidra {

class CodeUnit;
class Instruction;
class Register;
class PcodeOp;
class Varnode;

class RefTypeFactory {
public:
    static const RefType* get(int8_t type);

    static std::vector<const RefType*> getMemoryRefTypes();
    static std::vector<const RefType*> getStackRefTypes();
    static std::vector<const RefType*> getDataRefTypes();
    static std::vector<const RefType*> getExternalRefTypes();

    static const RefType* getDefaultRegisterRefType(CodeUnit* cu, Register* reg, int opIndex);
    static const RefType* getDefaultStackRefType(CodeUnit* cu, int opIndex);
    static const FlowType* getDefaultFlowType(Instruction* instr, const Address& toAddr, bool allowComputedFlowType);
    static const FlowType* getDefaultComputedFlowType(Instruction* instr);
    static const RefType* getDefaultMemoryRefType(CodeUnit* cu, int opIndex, const Address& toAddr, bool ignoreExistingReferences);

private:
    static const FlowType* getDefaultJumpOrCallFlowType(Instruction* instr);
    static const RefType* getMemRefType(Instruction* instr, const Address& memAddr);
    static const RefType* getLoadStoreRefType(const std::vector<PcodeOp*>& ops, int startOpSeq, const Address& offsetAddr, const RefType* refType);
    static bool isFlowOp(const PcodeOp* op);

    static constexpr uint64_t MASKS[9] = {
        0ULL, 0x0ffULL, 0x0ffffULL, 0x0ffffffULL, 0x0ffffffffULL,
        0x0ffffffffffULL, 0x0ffffffffffffULL, 0x0ffffffffffffffULL, 0xffffffffffffffffULL
    };
};

} // namespace ghidra
