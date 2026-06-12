#pragma once

#include <ghidra/Union.h>
#include <ghidra/CompositeInternal.h>

namespace ghidra {

class UnionInternal : public virtual Union, public virtual CompositeInternal {
};

} // namespace ghidra
