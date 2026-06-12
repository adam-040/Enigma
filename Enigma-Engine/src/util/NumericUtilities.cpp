/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file NumericUtilities.cpp
/// \brief Implementation of NumericUtilities

#include "ghidra/NumericUtilities.h"
#include <cctype>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace ghidra {

static const std::string HEX_PREFIX_x = "0x";
static const std::string HEX_PREFIX_X = "0X";

int64_t NumericUtilities::parseLong(const std::string& s) {
    return parseHelper(s, false, UINT64_MAX);
}

int64_t NumericUtilities::parseLong(const std::string& s, int64_t defaultValue) {
    try {
        return parseLong(s);
    } catch (const std::exception&) {
        return defaultValue;
    }
}

int64_t NumericUtilities::parseHexLong(const std::string& s) {
    return parseHelper(s, true, UINT64_MAX);
}

int32_t NumericUtilities::parseInt(const std::string& s) {
    int64_t val = parseHelper(s, false, 0xFFFFFFFFULL);
    return static_cast<int32_t>(val);
}

int32_t NumericUtilities::parseInt(const std::string& s, int32_t defaultValue) {
    try {
        return parseInt(s);
    } catch (const std::exception&) {
        return defaultValue;
    }
}

int64_t NumericUtilities::decodeBigInteger(const std::string& s) {
    std::string str = s;
    int p = 0;
    bool negative = false;
    if (!str.empty() && str[0] == '+') {
        p = 1;
    } else if (!str.empty() && str[0] == '-') {
        p = 1;
        negative = true;
    }

    std::string rest = str.substr(p);
    int64_t mag = 0;

    // Check for 0x prefix (case insensitive)
    if (rest.size() >= 2 && rest[0] == '0' && (rest[1] == 'x' || rest[1] == 'X')) {
        mag = std::stoll(rest.substr(2), nullptr, 16);
    }
    // Check for 0b prefix (case insensitive)
    else if (rest.size() >= 2 && rest[0] == '0' && (rest[1] == 'b' || rest[1] == 'B')) {
        mag = std::stoll(rest.substr(2), nullptr, 2);
    }
    // Check for 0 prefix (octal)
    else if (!rest.empty() && rest[0] == '0' && rest != "0") {
        mag = std::stoll(rest, nullptr, 8);
    }
    // Decimal
    else {
        mag = std::stoll(rest, nullptr, 10);
    }

    return negative ? -mag : mag;
}

std::string NumericUtilities::toHexString(int64_t value) {
    std::stringstream ss;
    ss << "0x" << std::hex << value;
    return ss.str();
}

std::string NumericUtilities::toHexString(int64_t value, int32_t size) {
    if (size > 0 && size < 8) {
        uint64_t mask = ~0ULL >> (8 * (8 - size));
        value &= static_cast<int64_t>(mask);
    }
    return toHexString(value);
}

std::string NumericUtilities::toSignedHexString(int64_t value) {
    std::stringstream ss;
    if (value < 0) {
        ss << "-";
    }
    ss << "0x" << std::hex << std::abs(static_cast<long long>(value));
    return ss.str();
}

uint64_t NumericUtilities::unsignedLongToUnsignedLong(int64_t value) {
    return static_cast<uint64_t>(value);
}

double NumericUtilities::unsignedLongToDouble(int64_t val) {
    double dVal = static_cast<double>(val & 0x7FFFFFFFFFFFFFFFLL);
    if (val < 0) {
        dVal += 0x1.0p63;
    }
    return dVal;
}

uint64_t NumericUtilities::getUnsignedAlignedValue(uint64_t unsignedValue, uint64_t alignment) {
    if (alignment == 0 || unsignedValue % alignment == 0) {
        return unsignedValue;
    }
    return ((unsignedValue + alignment - 1) / alignment) * alignment;
}

std::string NumericUtilities::formatNumber(int64_t number, int32_t radix) {
    return formatNumber(number, radix, SignednessFormatMode::DEFAULT);
}

std::string NumericUtilities::formatNumber(int64_t number, int32_t radix, SignednessFormatMode mode) {
    switch (mode) {
        case SignednessFormatMode::SIGNED:
            return signedIntegerRadixToString(number, radix);
        case SignednessFormatMode::UNSIGNED:
            return unsignedIntegerRadixToString(number, radix);
        case SignednessFormatMode::DEFAULT:
        default:
            return defaultIntegerRadixToString(number, radix);
    }
}

std::vector<uint8_t> NumericUtilities::convertStringToBytes(const std::string& hexString) {
    std::string cleaned;
    for (char c : hexString) {
        if (c != ' ' && c != ',') {
            cleaned += c;
        }
    }

    if (cleaned.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have an even number of characters");
    }

    std::vector<uint8_t> result;
    result.reserve(cleaned.length() / 2);
    for (size_t i = 0; i < cleaned.length(); i += 2) {
        std::string byteStr = cleaned.substr(i, 2);
        result.push_back(static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16)));
    }
    return result;
}

std::string NumericUtilities::convertBytesToString(const std::vector<uint8_t>& bytes) {
    return convertBytesToString(bytes, "");
}

std::string NumericUtilities::convertBytesToString(const std::vector<uint8_t>& bytes, const std::string& delimiter) {
    std::stringstream ss;
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i > 0 && !delimiter.empty()) {
            ss << delimiter;
        }
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// --- Private helpers ---

int64_t NumericUtilities::parseHelper(const std::string& s, bool forceHex, uint64_t max) {
    std::string str = s;
    // Trim
    auto trimStart = str.find_first_not_of(" \t\r\n");
    if (trimStart == std::string::npos) {
        throw std::invalid_argument("String to parse is empty");
    }
    auto trimEnd = str.find_last_not_of(" \t\r\n");
    str = str.substr(trimStart, trimEnd - trimStart + 1);

    if (str.empty()) {
        throw std::invalid_argument("String to parse is empty");
    }

    // Handle sign
    std::string sign;
    if (str[0] == '-' || str[0] == '+') {
        sign = str.substr(0, 1);
        str = str.substr(1);
    }

    // Detect radix
    bool hasHexPrefix = (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X'));
    int radix = (forceHex || hasHexPrefix) ? 16 : 10;

    if (hasHexPrefix) {
        str = str.substr(2);
    }

    if (str.empty() || str[0] == '-' || str[0] == '+') {
        throw std::invalid_argument("Cannot parse " + s);
    }

    uint64_t val = 0;
    try {
        val = std::stoull(str, nullptr, radix);
    } catch (const std::exception&) {
        throw std::invalid_argument("Cannot parse " + s);
    }

    if (val > max) {
        throw std::invalid_argument(str + " exceeds maximum data type size.");
    }

    // Apply sign
    int64_t result = static_cast<int64_t>(val);
    if (sign == "-") {
        result = -result;
    }

    return result;
}

std::string NumericUtilities::signedIntegerRadixToString(int64_t number, int32_t radix) {
    std::stringstream ss;
    switch (radix) {
        case 2:
            // Manual binary for signed
            if (number < 0) {
                ss << "-";
                number = -number;
            }
            {
                std::string bin;
                uint64_t n = static_cast<uint64_t>(number);
                if (n == 0) bin = "0";
                while (n > 0) { bin = char('0' + (n & 1)) + bin; n >>= 1; }
                ss << bin << "b";
            }
            break;
        case 8:
            ss << std::oct << number << "o";
            break;
        case 10:
            ss << number;
            break;
        case 16:
            {
                std::string h;
                if (number < 0) { ss << "-"; h = std::to_string(-static_cast<long long>(number)); }
                ss << std::hex << std::abs(static_cast<long long>(number)) << "h";
            }
            break;
        default:
            throw std::invalid_argument("Unsupported radix " + std::to_string(radix));
    }
    return ss.str();
}

std::string NumericUtilities::unsignedIntegerRadixToString(int64_t number, int32_t radix) {
    uint64_t unum = static_cast<uint64_t>(number);
    std::stringstream ss;
    switch (radix) {
        case 2:
            {
                std::string bin;
                uint64_t n = unum;
                if (n == 0) bin = "0";
                while (n > 0) { bin = char('0' + (n & 1)) + bin; n >>= 1; }
                ss << bin << "b";
            }
            break;
        case 8:
            ss << std::oct << unum << "o";
            break;
        case 10:
            ss << unum;
            break;
        case 16:
            ss << std::hex << unum << "h";
            break;
        default:
            throw std::invalid_argument("Unsupported radix " + std::to_string(radix));
    }
    return ss.str();
}

std::string NumericUtilities::defaultIntegerRadixToString(int64_t number, int32_t radix) {
    switch (radix) {
        case 2:
        case 8:
        case 16:
            return unsignedIntegerRadixToString(number, radix);
        case 10:
            return signedIntegerRadixToString(number, radix);
        default:
            throw std::invalid_argument("Unsupported radix " + std::to_string(radix));
    }
}

} // namespace ghidra
