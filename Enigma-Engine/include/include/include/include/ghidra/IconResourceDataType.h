#pragma once

#include <string>
#include <vector>
#include "ghidra/BitmapResourceDataType.h"
#include "ghidra/MemBuffer.h"

namespace ghidra {

class BitmapResource;

class IconResourceDataType : public BitmapResourceDataType {
public:
    IconResourceDataType();
    explicit IconResourceDataType(DataTypeManager* dtm);
    IconResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;

    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    const std::type_info& getValueClass(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;

protected:
    BitmapResource* getBitmapResource(MemBuffer* buf) override;
    int addComponents(MemBuffer* buf, BitmapResource* bmr, std::vector<DataTypeComponent*>& comps) override;
};

} // namespace ghidra
