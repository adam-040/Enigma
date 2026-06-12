/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/DataType.h>

namespace ghidra {

class MemBuffer;

class DataTypeInstance {
    DataType* dataType_ = nullptr;
    int length_ = 0;

    DataTypeInstance(DataType* dt, int length);

public:
    DataType* getDataType() const { return dataType_; }
    int getLength() const { return length_; }
    void setLength(int length) { length_ = length; }

    std::string toString() const;

    static DataTypeInstance* getDataTypeInstance(DataType* dataType, MemBuffer* buf,
                                                  bool useAlignedLength);
    static DataTypeInstance* getDataTypeInstance(DataType* dataType, int length,
                                                  bool useAlignedLength);
    static DataTypeInstance* getDataTypeInstance(DataType* dataType, MemBuffer* buf, int length,
                                                  bool useAlignedLength);
};

} // namespace ghidra
