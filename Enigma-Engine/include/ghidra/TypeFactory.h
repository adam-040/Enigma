#pragma once

#include <ghidra/DataType.h>
#include <ghidra/VoidDataType.h>
#include <ghidra/BooleanDataType.h>
#include <ghidra/SignedByteDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/ShortDataType.h>
#include <ghidra/UnsignedShortDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/UnsignedIntegerDataType.h>
#include <ghidra/LongDataType.h>
#include <ghidra/UnsignedLongDataType.h>
#include <ghidra/FloatDataType.h>
#include <ghidra/DoubleDataType.h>
#include <ghidra/StringDataType.h>
#include <ghidra/PointerDataType.h>
#include <ghidra/ArrayDataType.h>
#include <map>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

typedef int32_t int4;

class TypeFactory {
public:
    enum TypeType {
        TYPE_VOID,
        TYPE_BOOL,
        TYPE_INT,
        TYPE_UINT,
        TYPE_FLOAT,
        TYPE_DOUBLE,
        TYPE_LONGDOUBLE,
        TYPE_CHAR,
        TYPE_WCHAR,
        TYPE_CHAR16,
        TYPE_CHAR32,
        TYPE_POINTER,
        TYPE_ARRAY,
        TYPE_STRUCT,
        TYPE_UNION,
        TYPE_ENUM,
        TYPE_FUNCTION,
        TYPE_TYPEDEF,
        TYPE_BITFIELD,
        TYPE_UNKNOWN
    };

private:
    std::map<std::string, DataType*> nameMap;
    std::vector<DataType*> allTypes;
    DataType* voidType;
    DataType* boolType;
    DataType* int8Type;
    DataType* uint8Type;
    DataType* int16Type;
    DataType* uint16Type;
    DataType* int32Type;
    DataType* uint32Type;
    DataType* int64Type;
    DataType* uint64Type;
    DataType* floatType;
    DataType* doubleType;
    DataType* charType;
    int4 nextId;

public:
    TypeFactory();
    ~TypeFactory();

    DataType* getBase(TypeType tt, int4 size) const;
    DataType* getVoid() const { return voidType; }
    DataType* getBool() const { return boolType; }
    DataType* getInt(int4 size) const;
    DataType* getUInt(int4 size) const;
    DataType* getFloat() const { return floatType; }
    DataType* getDouble() const { return doubleType; }
    DataType* getChar() const { return charType; }

    DataType* getType(const std::string& name) const;
    DataType* getType(int4 id) const;

    PointerDataType* getTypePointer(int4 size, DataType* ptr, const std::string& name);
    ArrayDataType* getTypeArray(int4 numElements, DataType* elemType, const std::string& name);

    DataType* resolveNametype(const std::string& name) const;
    void registerType(DataType* type);
    void clear();

    int4 getNumTypes() const { return static_cast<int4>(allTypes.size()); }
    int4 getNextId() const { return nextId; }

    void setCodePointer(PointerDataType* type);
    void setVoidPointer(PointerDataType* type);

    PointerDataType* getCodePointer() const { return codePointer; }
    PointerDataType* getVoidPointer() const { return voidPointer; }

private:
    PointerDataType* codePointer = nullptr;
    PointerDataType* voidPointer = nullptr;
};

} // namespace ghidra
