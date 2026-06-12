#pragma once

#include <string>
#include <vector>
#include "ghidra/DynamicDataType.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"

namespace ghidra {

class DialogResourceDataType : public DynamicDataType {
public:
    DialogResourceDataType();
    explicit DialogResourceDataType(DataTypeManager* dtm);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;
    int getLength() const override { return -1; }
    int getLength(MemBuffer* buf, int maxLength) override { return -1; }

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    std::string getDefaultLabelPrefix() const override { return "Dialog"; }

    DataType* clone(DataTypeManager* dtm) const override;
    DataType* getReplacementBaseType() override { return &ByteDataType::dataType(); }
    void setDefaultSettings(Settings* settings) override { BuiltIn::setDefaultSettings(settings); }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return "Dialog"; }

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;
};

} // namespace ghidra
