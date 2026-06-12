/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighParamID.h
/// \brief High-level abstraction associated with a low level function for parameter measures.
/// Translated from: ghidra.program.model.pcode.HighParamID
#pragma once

#include <ghidra/PcodeSyntaxTree.h>
#include <ghidra/Address.h>
#include <string>
#include <vector>

namespace ghidra {
namespace pcode {

/**
 * ParamMeasure - placeholder for a parameter measure (input or output).
 */
struct ParamMeasure {
    int64_t hash = 0;
    int size = 0;
    int rank = 0;
    int64_t value = 0;
    bool isEmpty() const { return hash == 0 && size == 0; }
};

/**
 * High-level abstraction associated with a low level function. Used for storing
 * parameter measures (input/output) discovered by the decompiler.
 */
class HighParamID : public PcodeSyntaxTree {
public:
    static inline const std::string DECOMPILER_TAG_MAP = "decompiler_tags";

    HighParamID();
    HighParamID(void* function, void* language, void* compilerSpec, void* dtManager);

    const std::string& getFunctionName() const { return functionname; }
    const Address& getFunctionAddress() const { return functionaddress; }
    const std::string& getModelName() const { return modelname; }
    int getProtoExtraPop() const { return protoextrapop; }
    void* getFunction() const { return func; }

    void setFunctionName(const std::string& n) { functionname = n; }
    void setFunctionAddress(const Address& a) { functionaddress = a; }
    void setModelName(const std::string& m) { modelname = m; }
    void setProtoExtraPop(int p) { protoextrapop = p; }

    int getNumInputs() const { return static_cast<int>(inputlist.size()); }
    int getNumOutputs() const { return static_cast<int>(outputlist.size()); }
    const ParamMeasure& getInput(int i) const { return inputlist.at(i); }
    const ParamMeasure& getOutput(int i) const { return outputlist.at(i); }

    void decode(Decoder& decoder);

    void storeReturnToDatabase(bool storeDataTypes, int sourceType);
    void storeParametersToDatabase(bool storeDataTypes, int sourceType);

private:
    void* func;
    std::string functionname;
    Address functionaddress;
    std::string modelname;
    int protoextrapop;
    std::vector<ParamMeasure> inputlist;
    std::vector<ParamMeasure> outputlist;
};

}  // namespace pcode
}  // namespace ghidra
