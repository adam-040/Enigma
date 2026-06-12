#include <ghidra/TypeFactory.h>
#include <ghidra/StringDataType.h>
#include <stdexcept>

namespace ghidra {

TypeFactory::TypeFactory() : nextId(0) {
    voidType = new VoidDataType();
    boolType = new BooleanDataType();
    int8Type = new SignedByteDataType();
    uint8Type = new ByteDataType();
    int16Type = new ShortDataType();
    uint16Type = new UnsignedShortDataType();
    int32Type = new IntegerDataType();
    uint32Type = new UnsignedIntegerDataType();
    int64Type = new LongDataType();
    uint64Type = new UnsignedLongDataType();
    floatType = new FloatDataType();
    doubleType = new DoubleDataType();
    charType = new StringDataType();

    registerType(voidType);
    registerType(boolType);
    registerType(int8Type);
    registerType(uint8Type);
    registerType(int16Type);
    registerType(uint16Type);
    registerType(int32Type);
    registerType(uint32Type);
    registerType(int64Type);
    registerType(uint64Type);
    registerType(floatType);
    registerType(doubleType);
    registerType(charType);
}

TypeFactory::~TypeFactory() {
    clear();
}

DataType* TypeFactory::getBase(TypeType tt, int4 size) const {
    switch (tt) {
        case TYPE_VOID: return voidType;
        case TYPE_BOOL: return boolType;
        case TYPE_INT:
            if (size == 1) return int8Type;
            if (size == 2) return int16Type;
            if (size == 4) return int32Type;
            if (size == 8) return int64Type;
            break;
        case TYPE_UINT:
            if (size == 1) return uint8Type;
            if (size == 2) return uint16Type;
            if (size == 4) return uint32Type;
            if (size == 8) return uint64Type;
            break;
        case TYPE_FLOAT: return floatType;
        case TYPE_DOUBLE: return doubleType;
        case TYPE_CHAR: return charType;
        default: break;
    }
    return nullptr;
}

DataType* TypeFactory::getInt(int4 size) const {
    return getBase(TYPE_INT, size);
}

DataType* TypeFactory::getUInt(int4 size) const {
    return getBase(TYPE_UINT, size);
}

DataType* TypeFactory::getType(const std::string& name) const {
    auto it = nameMap.find(name);
    return (it != nameMap.end()) ? it->second : nullptr;
}

DataType* TypeFactory::getType(int4 id) const {
    if (id >= 0 && id < static_cast<int4>(allTypes.size())) {
        return allTypes[id];
    }
    return nullptr;
}

PointerDataType* TypeFactory::getTypePointer(int4 size, DataType* ptr, const std::string& name) {
    auto* type = new PointerDataType(ptr, size, nullptr, false);
    registerType(type);
    (void)name;
    return type;
}

ArrayDataType* TypeFactory::getTypeArray(int4 numElements, DataType* elemType, const std::string& name) {
    auto* type = new ArrayDataType(elemType, numElements, -1, nullptr, false);
    registerType(type);
    (void)name;
    return type;
}

DataType* TypeFactory::resolveNametype(const std::string& name) const {
    return getType(name);
}

void TypeFactory::registerType(DataType* type) {
    if (!type) return;
    allTypes.push_back(type);
    nameMap[type->getName()] = type;
}

void TypeFactory::clear() {
    for (auto* type : allTypes) {
        delete type;
    }
    allTypes.clear();
    nameMap.clear();
    nextId = 0;

    voidType = nullptr;
    boolType = nullptr;
    int8Type = nullptr;
    uint8Type = nullptr;
    int16Type = nullptr;
    uint16Type = nullptr;
    int32Type = nullptr;
    uint32Type = nullptr;
    int64Type = nullptr;
    uint64Type = nullptr;
    floatType = nullptr;
    doubleType = nullptr;
    charType = nullptr;
}

void TypeFactory::setCodePointer(PointerDataType* type) {
    codePointer = type;
}

void TypeFactory::setVoidPointer(PointerDataType* type) {
    voidPointer = type;
}

} // namespace ghidra
