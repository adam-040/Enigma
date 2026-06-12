#pragma once

#include <string>
#include "ghidra/IconResourceDataType.h"

namespace ghidra {

class IconMaskResourceDataType : public IconResourceDataType {
public:
    IconMaskResourceDataType();
    explicit IconMaskResourceDataType(DataTypeManager* dtm);
    IconMaskResourceDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm);

    std::string getDescription() const override;
    std::string getMnemonic(Settings* settings) const override;

    DataType* clone(DataTypeManager* dtm) const override;
};

} // namespace ghidra
