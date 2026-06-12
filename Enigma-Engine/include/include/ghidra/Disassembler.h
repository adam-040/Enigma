/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file Disassembler.h
/// \brief Adapter interface for disassembly (Capstone/Sleigh-based)
/// Bridges external disassembler to Enigma Engine Program Model
#pragma once

#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace ghidra {

class ProgramDB;
class Listing;
class Instruction;
class Memory;

struct DisassembledInstruction {
    Address address;
    std::string mnemonic;
    std::vector<std::string> operands;
    int length;
    FlowType* flowType;
    uint64_t bytes[16];
    int byteCount;
};

class Disassembler {
public:
    virtual ~Disassembler() = default;

    virtual bool initialize(const std::string& architecture, int bitness, bool bigEndian) = 0;

    virtual DisassembledInstruction disassembleOne(const std::vector<uint8_t>& bytes, uint64_t address) = 0;

    virtual std::vector<DisassembledInstruction> disassembleRange(
        const std::vector<uint8_t>& bytes,
        uint64_t startAddress,
        size_t maxSize,
        size_t maxInstructions) = 0;

    virtual bool populateListing(ProgramDB* program, const Address& startAddr, const Address& endAddr) = 0;

    virtual std::string getArchitecture() const = 0;
    virtual int getInstructionAlignment() const = 0;

    static FlowType* determineFlowType(const std::string& mnemonic, const std::vector<std::string>& operands);
    void setProgram(ProgramDB* program);

protected:
    ProgramDB* program_ = nullptr;
};

std::unique_ptr<Disassembler> createDisassembler(const std::string& architecture, int bitness, bool bigEndian);

} // namespace ghidra
