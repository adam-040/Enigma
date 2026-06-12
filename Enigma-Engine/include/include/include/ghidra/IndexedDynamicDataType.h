#pragma once

#include <ghidra/DynamicDataType.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace ghidra {

/**
 * Indexed Dynamic Data Type template.  Used to create instances of the data type at
 * a given location in memory based on the data found there.
 * 
 * This data struture is used when there is a structure with key field in a header.
 * The key field, which is a number, sets which of a number of structures follows the header.
 */
class IndexedDynamicDataType : public DynamicDataType {
public:
    static const std::string NULL_BODY_DESCRIPTION;

    IndexedDynamicDataType(const std::string& name, const std::string& description,
                           DataType* header, const std::vector<int64_t>& keys,
                           const std::vector<DataType*>& structs,
                           int64_t indexOffset, int indexSize, int64_t mask, DataTypeManager* dtm);

    IndexedDynamicDataType(const std::string& name, const std::string& description,
                           DataType* header, int64_t singleKey,
                           DataType* structIfSingle, DataType* structIfDefault,
                           int64_t indexOffset, int indexSize, int64_t mask, DataTypeManager* dtm);

    ~IndexedDynamicDataType() override = default;

    DataType* clone(DataTypeManager* dtm) const override;
    int getLength() const override { return -1; }
    std::string getDescription() const override { return description_; }
    std::string getRepresentation(MemBuffer* buf, Settings* settings, int length) const override;
    int getLength(MemBuffer* buf, int maxLength) override;
    DataType* getReplacementBaseType() override;
    std::string getCTypeDeclaration(DataOrganization* dataOrganization) override { return getName(); }
    void setDefaultSettings(Settings* settings) override {}

protected:
    std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) override;

    std::string description_;
    DataType* header_;
    std::vector<int64_t> keys_;
    std::vector<DataType*> structs_;
    int64_t indexOffset_;
    int indexSize_;
    int64_t mask_;

private:
    std::unordered_map<int64_t, int> table_;
};

} // namespace ghidra
