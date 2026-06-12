/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file IllegalCharCppTransformer.cpp
/// \brief Implementation of IllegalCharCppTransformer.
#include "ghidra/IllegalCharCppTransformer.h"
#include <cctype>

namespace ghidra {

IllegalCharCppTransformer::IllegalCharCppTransformer() {
}

static int getLegalFlags(unsigned char c) {
    switch (c) {
    case '_': return IllegalCharCppTransformer::AFTER_FIRST_CHAR |
                     IllegalCharCppTransformer::TEMPLATE |
                     IllegalCharCppTransformer::OPERATOR |
                     IllegalCharCppTransformer::FIRST_CHAR;
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return IllegalCharCppTransformer::AFTER_FIRST_CHAR |
               IllegalCharCppTransformer::TEMPLATE |
               IllegalCharCppTransformer::OPERATOR;
    case '*': return IllegalCharCppTransformer::TEMPLATE |
                     IllegalCharCppTransformer::OPERATOR;
    case ':': return IllegalCharCppTransformer::TEMPLATE;
    case '(': case ')': case '[': case ']':
        return IllegalCharCppTransformer::TEMPLATE |
               IllegalCharCppTransformer::OPERATOR;
    case ',': return IllegalCharCppTransformer::TEMPLATE;
    case '&': case '+': case '-': case '|':
    case '=': case '!': case '/': case '%': case '^':
        return IllegalCharCppTransformer::OPERATOR;
    case '~': return IllegalCharCppTransformer::TEMPLATE |
                     IllegalCharCppTransformer::OPERATOR |
                     IllegalCharCppTransformer::FIRST_CHAR;
    }
    return 0;
}

std::string IllegalCharCppTransformer::simplify(const std::string& input) {
    int templateDepth = 0;
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (std::isalpha(c)) {
            result.push_back(static_cast<char>(c));
            continue;
        }
        if (c == '<') {
            templateDepth++;
            result.push_back('<');
            continue;
        }
        if (c == '>') {
            templateDepth--;
            if (templateDepth < 0) templateDepth = 0;
            result.push_back('>');
            continue;
        }
        if (c >= 128) {
            result.push_back('_');
            continue;
        }
        int val = getLegalFlags(c);
        if (val == 0) {
            result.push_back('_');
            continue;
        }
        bool ok = ((val & AFTER_FIRST_CHAR) != 0 && i > 0) ||
                  ((val & FIRST_CHAR) != 0 && i == 0) ||
                  ((val & TEMPLATE) != 0 && templateDepth > 0) ||
                  ((val & OPERATOR) != 0 && i >= 8 && i <= 10 &&
                   input.substr(0, 8) == "operator");
        if (ok) {
            result.push_back(static_cast<char>(c));
        } else {
            result.push_back('_');
        }
    }
    return result;
}

} // namespace ghidra
