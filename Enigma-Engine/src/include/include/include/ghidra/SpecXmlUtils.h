#pragma once

#include <string>
#include <cstdlib>
#include <stdexcept>

namespace ghidra {

struct SpecXmlUtils {
    static int decodeInt(const std::string& s) {
        if (s.empty()) return 0;
        return std::stoi(s, nullptr, 0);
    }

    static long decodeLong(const std::string& s) {
        if (s.empty()) return 0;
        return std::stol(s, nullptr, 0);
    }

    static bool decodeBoolean(const std::string& s) {
        return s == "true" || s == "yes" || s == "1";
    }
};

} // namespace ghidra
