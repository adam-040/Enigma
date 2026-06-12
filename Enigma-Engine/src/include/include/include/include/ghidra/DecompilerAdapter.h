/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DecompilerAdapter.h
/// \brief Adapter interface for Ghidra Decompiler (C++ native)
/// Bridges Ghidra's C++ decompiler to Enigma Engine Program Model
#pragma once

#include <ghidra/Address.h>
#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class ProgramDB;
class Function;

struct DecompiledFunction {
    std::string cCode;
    std::string highLevelIR;
    std::vector<std::string> warnings;
    bool success;
};

struct PcodeOutput {
    Address address;
    std::string mnemonic;
    std::vector<std::string> inputs;
    std::vector<std::string> outputs;
};

class DecompilerAdapter {
public:
    virtual ~DecompilerAdapter() = default;

    virtual bool initialize(ProgramDB* program) = 0;

    virtual DecompiledFunction decompileFunction(Function* func, int maxSeconds = 30) = 0;

    virtual void generatePcode(Function* func, std::vector<PcodeOutput>& result) = 0;

    virtual std::string getDecompilerVersion() const = 0;

    virtual void setOption(const std::string& name, const std::string& value) = 0;

protected:
    ProgramDB* program_ = nullptr;
};

std::unique_ptr<DecompilerAdapter> createDecompilerAdapter();

} // namespace ghidra
