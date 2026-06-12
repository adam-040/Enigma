#pragma once

#include "MachException.h"

namespace ghidra {

class ObsoleteException : public MachException {
public:
    ObsoleteException() : MachException("Obsolete") {}
};

} // namespace ghidra
