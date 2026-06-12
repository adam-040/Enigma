/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PrototypeModelError.h
/// \brief A PrototypeModel cloned from another, but marked as an error placeholder
/// Translated from: ghidra.program.model.lang.PrototypeModelError
#pragma once

#include "ghidra/PrototypeModel.h"

namespace ghidra {

class PrototypeModelError : public PrototypeModel {
public:
    PrototypeModelError(const std::string& name, const PrototypeModel& copyModel)
        : PrototypeModel(name, copyModel.getCallingConvention(), copyModel.isInferred()) {
        setHasThisParameter(copyModel.hasThisParameter());
        setHasReturnAddressSpace(copyModel.hasReturnAddressSpace());
        setThisBeforeReturnPointer(copyModel.isThisBeforeReturnPointer());
        setStackAlignment(copyModel.getStackAlignment());
        setStackParameterAlignment(copyModel.getStackParameterAlignment());
        setStackParameterOffset(copyModel.getStackParameterOffset());
        setStackshift(copyModel.getStackshift());
        setExtraPop(copyModel.getExtraPop());
        setNoReturn(copyModel.isNoReturn());
        setInline(copyModel.isInline());
        setConstructor(copyModel.isConstructor());
        setDestructor(copyModel.isDestructor());
    }

    bool isErrorPlaceholder() const override { return true; }
};

} // namespace ghidra
