#pragma once

#include <string>
#include <cstdint>
#include "ghidra/BuiltIn.h"
#include "ghidra/Dynamic.h"

namespace ghidra {

class MemBuffer;

class AUDataType : public BuiltIn, public virtual Dynamic {
public:
    AUDataType();
    explicit AUDataType(DataTypeManager* dtm);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;
    int getLength() const override;
    int getLength(MemBuffer* buf, int maxLength) override;
    bool canSpecifyLength() override { return false; }

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    std::string getDefaultLabelPrefix() const override { return "AU"; }
    std::string getDefaultLabelPrefix(MemBuffer* buf, Settings* settings, int len, DataTypeDisplayOptions* options) const override { return getDefaultLabelPrefix(); }

    DataType* clone(DataTypeManager* dtm) const override;
    DataType* getReplacementBaseType() const override;
    DataType* getReplacementBaseType() override;
    void setDefaultSettings(Settings* settings) override { BuiltIn::setDefaultSettings(settings); }

    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override;

    static bool isMagic(const uint8_t* data, int length);
};

} // namespace ghidra
