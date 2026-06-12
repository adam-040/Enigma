#pragma once

#include <ghidra/DynamicDataType.h>
#include <string>
#include <vector>

namespace ghidra {

/**
 * Structured Dynamic Data type.
 * 
 * Dynamic Structure that is built by adding data types to it.
 * 
 * NOTE: This is a special Dynamic data-type which can only appear as a component
 * created by a Dynamic data-type
 */
class StructuredDynamicDataType : public DynamicDataType {
public:
    StructuredDynamicDataType(const std::string& name, const std::string& description, DataTypeManager* dtm);
    ~StructuredDynamicDataType() override = default;

    DataType* clone(DataTypeManager* dtm) const override;
    int getLength() const override { return -1; }
    std::string getDescription() const override { return description_; }
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override;
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}

    void add(DataType* data, const std::string& componentName, const std::string& componentDescription);
    void setComponents(const std::vector<DataType*>& components, 
                       const std::vector<std::string>& componentNames,
                       const std::vector<std::string>& componentDescs);

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;

    std::string description_;
    std::vector<DataType*> components_;
    std::vector<std::string> componentNames_;
    std::vector<std::string> componentDescs_;
};

} // namespace ghidra
