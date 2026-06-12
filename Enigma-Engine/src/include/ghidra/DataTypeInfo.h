/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DataTypeInfo.h
/// \brief Immutable metadata about a data type: handle, length, alignment.
/// Translated from: ghidra.program.model.util.DataTypeInfo
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace ghidra {

class DataTypeInfo {
public:
    DataTypeInfo(void* dataTypeHandle, int dataTypeLength, int dataTypeAlignment)
        : dataTypeHandle_(dataTypeHandle), dataTypeLength_(dataTypeLength),
          dataTypeAlignment_(dataTypeAlignment) {}

    DataTypeInfo(const DataTypeInfo& other)
        : dataTypeHandle_(other.dataTypeHandle_), dataTypeLength_(other.dataTypeLength_),
          dataTypeAlignment_(other.dataTypeAlignment_) {}

    void* getDataTypeHandle() const { return dataTypeHandle_; }
    int getDataTypeLength() const { return dataTypeLength_; }
    int getDataTypeAlignment() const { return dataTypeAlignment_; }

    bool equals(const DataTypeInfo& other) const {
        return dataTypeAlignment_ == other.dataTypeAlignment_ &&
               dataTypeHandle_ == other.dataTypeHandle_ &&
               dataTypeLength_ == other.dataTypeLength_;
    }

    int hashCode() const {
        int result = 1;
        result = 31 * result + dataTypeAlignment_;
        result = 31 * result + dataTypeLength_;
        result = 31 * result + (dataTypeHandle_ ? (int)(intptr_t)dataTypeHandle_ : 0);
        return result;
    }

protected:
    void* dataTypeHandle_;
    int dataTypeLength_;
    int dataTypeAlignment_;
};

class CompositeDataTypeElementInfo : public DataTypeInfo {
public:
    CompositeDataTypeElementInfo(void* dataTypeHandle, int dataTypeOffset,
                                 int dataTypeLength, int dataTypeAlignment)
        : DataTypeInfo(dataTypeHandle, dataTypeLength, dataTypeAlignment),
          dataTypeOffset_(dataTypeOffset) {}

    CompositeDataTypeElementInfo(const DataTypeInfo& info, int dataTypeOffset)
        : DataTypeInfo(info), dataTypeOffset_(dataTypeOffset) {}

    int getDataTypeOffset() const { return dataTypeOffset_; }

    bool equals(const CompositeDataTypeElementInfo& other) const {
        return dataTypeOffset_ == other.dataTypeOffset_ && DataTypeInfo::equals(other);
    }

    int hashCode() const {
        int result = DataTypeInfo::hashCode();
        result = 31 * result + dataTypeOffset_;
        return result;
    }

    std::string toString() const {
        char buf[64];
        snprintf(buf, sizeof(buf), "%p/%d:(%d,%d)",
                 dataTypeHandle_, dataTypeAlignment_, dataTypeOffset_, dataTypeLength_);
        return buf;
    }

private:
    int dataTypeOffset_;
};

} // namespace ghidra
