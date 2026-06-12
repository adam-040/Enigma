#pragma once

#include <ghidra/Structure.h>
#include <ghidra/CompositeInternal.h>

namespace ghidra {

class StructureInternal : public virtual Structure, public virtual CompositeInternal {
};

} // namespace ghidra
