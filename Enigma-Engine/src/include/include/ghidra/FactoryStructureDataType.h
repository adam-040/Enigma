#pragma once

#include <ghidra/BuiltIn.h>
#include <ghidra/FactoryDataType.h>
#include <ghidra/Structure.h>

namespace ghidra {

/**
 * Abstract class used to create specialized data structures that act like
 * a Structure and create a new Dynamic structure each time they are used.
 */
class FactoryStructureDataType : public BuiltIn, public virtual FactoryDataType {
public:
    FactoryStructureDataType(const std::string& name, DataTypeManager* dtm);
    ~FactoryStructureDataType() override = default;

    int getLength() const override { return -1; }
    std::string getDescription() const override { return "Dynamic Data Type should not be instantiated directly"; }
    
    DataType* getDataType(MemBuffer* buf) override;

protected:
    virtual void populateDynamicStructure(MemBuffer* buf, Structure* structDt) = 0;
    virtual Structure* setCategoryPath(Structure* structDt, MemBuffer* buf);

private:
    void setCategory(DataType* dt, const CategoryPath& path);
};

} // namespace ghidra
