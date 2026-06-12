/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file HighCodeSymbol.h
/// \brief A global symbol as part of the decompiler's model of a function.
/// Translated from: ghidra.program.model.pcode.HighCodeSymbol
#pragma once

#include "ghidra/HighSymbol.h"

namespace ghidra {
namespace pcode {

class HighFunction;

/**
 * A global symbol as part of the decompiler's model of a function.
 * Currently a stub: CodeSymbol and Data backing objects are opaque void* since
 * those Ghidra Java interfaces are not yet ported.
 */
class HighCodeSymbol : public HighSymbol {
public:
    HighCodeSymbol(void* sym, HighFunction* func);
    HighCodeSymbol(int64_t id, const Address& addr, DataType* dataType, int sz, HighFunction* func);
    HighCodeSymbol(int64_t id, const std::string& nm, void* data, void* dtmanage);

    bool isGlobal() const override { return true; }

    void* getCodeSymbol() const { return backingCodeSymbol; }
    void* getData() const { return backingData; }

    int getSize() const override { return 1; }

    void decode(Decoder& decoder) override;

private:
    void* backingCodeSymbol;
    void* backingData;
};

}  // namespace pcode
}  // namespace ghidra
