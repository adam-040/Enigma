/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/Group.h>
#include <ghidra/AddressSetView.h>

namespace ghidra {

class ProgramFragment : public virtual Group, public virtual AddressSetView {
public:
    virtual ~ProgramFragment() = default;

    using Group::contains;
    using AddressSetView::contains;

    virtual Address getMinAddress() const override = 0;
    virtual Address getMaxAddress() const override = 0;

    virtual bool contains(CodeUnit* codeUnit) const override = 0;
    virtual void move(const Address& min, const Address& max) = 0;
};

} // namespace ghidra
