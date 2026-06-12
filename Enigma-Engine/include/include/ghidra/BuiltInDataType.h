#pragma once

#include <ghidra/DataType.h>
#include <string>

namespace ghidra {

class DataOrganization;
class Settings;

class BuiltInDataType : public virtual DataType {
public:
    virtual std::string getCTypeDeclaration(DataOrganization* dataOrganization) = 0;
    virtual void setDefaultSettings(Settings* settings) = 0;
};

} // namespace ghidra
