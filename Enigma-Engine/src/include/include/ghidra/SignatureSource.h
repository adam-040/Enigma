#pragma once

#include <string>

namespace ghidra {

enum class SignatureSource : uint8_t {
    UNKNOWN           = 0,
    IMPORT_HEURISTIC  = 1,
    KNOWN_LIBRARY     = 2,
    PDB               = 3,
    DWARF             = 4,
    USER              = 5,
    ANALYSIS          = 6
};

inline const char* signatureSourceName(SignatureSource s) {
    switch (s) {
        case SignatureSource::UNKNOWN:           return "unknown";
        case SignatureSource::IMPORT_HEURISTIC:   return "import_heuristic";
        case SignatureSource::KNOWN_LIBRARY:      return "known_library";
        case SignatureSource::PDB:                return "pdb";
        case SignatureSource::DWARF:              return "dwarf";
        case SignatureSource::USER:               return "user";
        case SignatureSource::ANALYSIS:           return "analysis";
        default:                                  return "invalid";
    }
}

inline bool signatureSourceOutranks(SignatureSource candidate, SignatureSource existing) {
    return static_cast<uint8_t>(candidate) > static_cast<uint8_t>(existing);
}

} // namespace ghidra
