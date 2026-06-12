#include <ghidra/FactoryStructureDataType.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/Union.h>
#include <ghidra/TypeDef.h>
#include <ghidra/Pointer.h>
#include <ghidra/Array.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/DataTypeComponent.h>

namespace ghidra {

FactoryStructureDataType::FactoryStructureDataType(const std::string& name, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm) {
}

DataType* FactoryStructureDataType::getDataType(MemBuffer* buf) {
    Structure* structDt = new StructureDataType(getName(), 0, getDataTypeManager());
    if (buf != nullptr) {
        populateDynamicStructure(buf, structDt);
        structDt = setCategoryPath(structDt, buf);
    }
    return structDt;
}

Structure* FactoryStructureDataType::setCategoryPath(Structure* structDt, MemBuffer* buf) {
    CategoryPath path = CategoryPath::ROOT();
    try {
        CategoryPath parent(CategoryPath::ROOT(), getName());
        path = CategoryPath(parent, buf->getAddress().toString());
    } catch (...) {
        // ignore
    }
    setCategory(structDt, path);
    return structDt;
}

void FactoryStructureDataType::setCategory(DataType* dt, const CategoryPath& path) {
    if (dt == nullptr) {
        return;
    }

    try {
        dt->setCategoryPath(path);
    } catch (...) {
        // ignore DuplicateNameException or similar
    }

    if (auto* structDt = dynamic_cast<Structure*>(dt)) {
        for (auto* comp : structDt->getDefinedComponents()) {
            setCategory(comp->getDataType(), path);
        }
    } else if (auto* unionDt = dynamic_cast<Union*>(dt)) {
        for (auto* comp : unionDt->getComponents()) {
            setCategory(comp->getDataType(), path);
        }
    } else if (auto* typeDef = dynamic_cast<TypeDef*>(dt)) {
        setCategory(typeDef->getDataType(), path);
    } else if (auto* ptr = dynamic_cast<Pointer*>(dt)) {
        setCategory(ptr->getDataType(), path);
    } else if (auto* array = dynamic_cast<Array*>(dt)) {
        setCategory(array->getDataType(), path);
    }
}

} // namespace ghidra
