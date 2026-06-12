/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file StorageClass.h
/// \brief Data-type class for the purpose of assigning storage
/// Translated from: ghidra.program.model.lang.StorageClass
#pragma once

#include <string>
#include <stdexcept>

namespace ghidra {

enum class StorageClass {
    GENERAL,
    FLOAT,
    PTR,
    HIDDENRET,
    VECTOR,
    CLASS1,
    CLASS2,
    CLASS3,
    CLASS4
};

inline int getStorageClassValue(StorageClass sc) {
    switch (sc) {
        case StorageClass::GENERAL: return 0;
        case StorageClass::FLOAT: return 1;
        case StorageClass::PTR: return 2;
        case StorageClass::HIDDENRET: return 3;
        case StorageClass::VECTOR: return 4;
        case StorageClass::CLASS1: return 100;
        case StorageClass::CLASS2: return 101;
        case StorageClass::CLASS3: return 102;
        case StorageClass::CLASS4: return 103;
    }
    return -1;
}

inline std::string toString(StorageClass sc) {
    switch (sc) {
        case StorageClass::GENERAL: return "general";
        case StorageClass::FLOAT: return "float";
        case StorageClass::PTR: return "ptr";
        case StorageClass::HIDDENRET: return "hiddenret";
        case StorageClass::VECTOR: return "vector";
        case StorageClass::CLASS1: return "class1";
        case StorageClass::CLASS2: return "class2";
        case StorageClass::CLASS3: return "class3";
        case StorageClass::CLASS4: return "class4";
    }
    return "unknown";
}

inline StorageClass storageClassFromString(const std::string& val) {
    if (val == "general") return StorageClass::GENERAL;
    if (val == "float") return StorageClass::FLOAT;
    if (val == "ptr") return StorageClass::PTR;
    if (val == "hiddenret") return StorageClass::HIDDENRET;
    if (val == "vector") return StorageClass::VECTOR;
    if (val == "class1") return StorageClass::CLASS1;
    if (val == "class2") return StorageClass::CLASS2;
    if (val == "class3") return StorageClass::CLASS3;
    if (val == "class4") return StorageClass::CLASS4;
    throw std::invalid_argument("Unknown storage class: " + val);
}

} // namespace ghidra
