/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file SourceType.h
/// \brief Source type enumeration for symbols and program elements
/// Translated from: ghidra.program.model.symbol.SourceType
#pragma once

#include <string>
#include <stdexcept>

namespace ghidra {

enum class SourceType {
    DEFAULT = 0,
    ANALYSIS = 1,
    USER_DEFINED = 2,
    IMPORTED = 3,
    USER_DEFINED_ADD = 4,
    AI = 5
};

inline std::string sourceTypeToString(SourceType type) {
    switch (type) {
        case SourceType::DEFAULT: return "DEFAULT";
        case SourceType::ANALYSIS: return "ANALYSIS";
        case SourceType::USER_DEFINED: return "USER_DEFINED";
        case SourceType::IMPORTED: return "IMPORTED";
        case SourceType::USER_DEFINED_ADD: return "USER_DEFINED_ADD";
        case SourceType::AI: return "AI";
    }
    return "UNKNOWN";
}

inline SourceType parseSourceType(int value) {
    switch (value) {
        case 0: return SourceType::DEFAULT;
        case 1: return SourceType::ANALYSIS;
        case 2: return SourceType::USER_DEFINED;
        case 3: return SourceType::IMPORTED;
        case 4: return SourceType::USER_DEFINED_ADD;
        case 5: return SourceType::AI;
        default: throw std::invalid_argument("Invalid SourceType value: " + std::to_string(value));
    }
}

inline bool isUserDefined(SourceType type) {
    return type == SourceType::USER_DEFINED || type == SourceType::USER_DEFINED_ADD;
}

// Ghidra-compatible SourceType priority helpers
inline SourceType getSourceType(int storageId) {
    switch (storageId) {
        case 0: return SourceType::ANALYSIS;
        case 1: return SourceType::USER_DEFINED;
        case 2: return SourceType::DEFAULT;
        case 3: return SourceType::IMPORTED;
        case 4: return SourceType::AI;
        default: throw std::out_of_range("SourceType storage ID not defined: " + std::to_string(storageId));
    }
}

inline int getPriority(SourceType st) {
    switch (st) {
        case SourceType::DEFAULT: return 1;
        case SourceType::ANALYSIS: return 2;
        case SourceType::AI: return 2;
        case SourceType::IMPORTED: return 3;
        case SourceType::USER_DEFINED: return 4;
        case SourceType::USER_DEFINED_ADD: return 4;
    }
    return 0;
}

inline int getStorageId(SourceType st) {
    switch (st) {
        case SourceType::DEFAULT: return 2;
        case SourceType::ANALYSIS: return 0;
        case SourceType::AI: return 4;
        case SourceType::IMPORTED: return 3;
        case SourceType::USER_DEFINED: return 1;
        case SourceType::USER_DEFINED_ADD: return 1;
    }
    return 0;
}

inline std::string getDisplayString(SourceType st) {
    switch (st) {
        case SourceType::DEFAULT: return "Default";
        case SourceType::ANALYSIS: return "Analysis";
        case SourceType::AI: return "AI";
        case SourceType::IMPORTED: return "Imported";
        case SourceType::USER_DEFINED: return "User Defined";
        case SourceType::USER_DEFINED_ADD: return "User Defined";
    }
    return "Unknown";
}

inline bool isHigherPriorityThan(SourceType a, SourceType b) {
    return getPriority(a) > getPriority(b);
}

inline bool isHigherOrEqualPriorityThan(SourceType a, SourceType b) {
    return getPriority(a) >= getPriority(b);
}

inline bool isLowerPriorityThan(SourceType a, SourceType b) {
    return getPriority(a) < getPriority(b);
}

inline bool isLowerOrEqualPriorityThan(SourceType a, SourceType b) {
    return getPriority(a) <= getPriority(b);
}

} // namespace ghidra
