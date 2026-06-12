/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ConstantPool.h
/// \brief Class for manipulating deferred constant systems (e.g. JVM constant pool)
/// Translated from: ghidra.program.model.lang.ConstantPool
#pragma once

#include <ghidra/DataType.h>
#include <ghidra/Encoder.h>
#include <string>
#include <vector>

namespace ghidra {

class PcodeDataTypeManager;

class ConstantPool {
public:
    static constexpr int PRIMITIVE       = 0;
    static constexpr int STRING_LITERAL  = 1;
    static constexpr int CLASS_REFERENCE = 2;
    static constexpr int POINTER_METHOD  = 3;
    static constexpr int POINTER_FIELD   = 4;
    static constexpr int ARRAY_LENGTH    = 5;
    static constexpr int INSTANCE_OF     = 6;
    static constexpr int CHECK_CAST      = 7;

    struct Record {
        int tag = PRIMITIVE;
        std::string token;
        int64_t value = 0;
        std::vector<uint8_t> byteData;
        DataType* type = nullptr;
        bool isConstructor = false;

        void encode(Encoder& encoder, int64_t ref, PcodeDataTypeManager* dtmanager);

        void setUTF8Data(const std::string& val);
    };

    virtual ~ConstantPool() = default;
    virtual Record getRecord(const std::vector<int64_t>& ref) = 0;
};

} // namespace ghidra
