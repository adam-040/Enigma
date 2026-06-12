#pragma once

#include <string>
#include <vector>
#include "ghidra/DynamicDataType.h"
#include "ghidra/Resource.h"
#include "ghidra/MemBuffer.h"
#include "ghidra/ByteDataType.h"

namespace ghidra {

class BitmapResource;

class BitmapResourceDataType : public DynamicDataType, public virtual Resource {
public:
    BitmapResourceDataType();
    explicit BitmapResourceDataType(DataTypeManager* dtm);
    BitmapResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;
    int getLength() const override { return -1; }
    int getLength(MemBuffer* buf, int maxLength) override { return -1; }

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    const std::type_info& getValueClass(Settings* settings) const override;
    std::string getDefaultLabelPrefix() const override { return "BITMAP"; }

    DataType* clone(DataTypeManager* dtm) const override;
    DataType* getReplacementBaseType() override { return &ByteDataType::dataType(); }
    void setDefaultSettings(Settings* settings) override { BuiltIn::setDefaultSettings(settings); }
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return "Bitmap"; }

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;

    virtual BitmapResource* getBitmapResource(MemBuffer* buf);
    virtual int addComponents(MemBuffer* buf, BitmapResource* bmr, std::vector<DataTypeComponent*>& comps);
    int addComp(DataType* dataType, int length, const std::string& fieldName,
                std::vector<DataTypeComponent*>& comps, int offset);
    int addComp(DataType* dataType, int length, const std::string& fieldName,
                std::vector<DataTypeComponent*>& comps, int offset, MemBuffer* buf);
};

} // namespace ghidra
