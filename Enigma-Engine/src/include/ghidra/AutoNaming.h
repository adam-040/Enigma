#pragma once

#include <string>
#include <sstream>

#include "Address.h"

namespace ghidra {

class AutoNaming {
public:
    static std::string name(const char* prefix, const Address& addr) {
        return nameVal(prefix, static_cast<uint64_t>(addr.getOffset()));
    }

    static std::string nameVal(const char* prefix, uint64_t val) {
        std::ostringstream ss;
        ss << prefix << "_0x" << std::hex << val;
        return ss.str();
    }
};

} // namespace ghidra
