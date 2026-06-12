#pragma once

#include <ghidra/BuiltIn.h>
#include <ghidra/Dynamic.h>
#include <ghidra/Address.h>
#include <ghidra/MemBuffer.h>
#include <ghidra/DataTypeComponent.h>
#include <vector>
#include <unordered_map>
#include <memory>

namespace ghidra {

/**
 * Interface for dataTypes that don't get applied, but instead generate dataTypes
 * on the fly based on the data.
 */
class DynamicDataType : public BuiltIn, public virtual Dynamic {
public:
    explicit DynamicDataType(const std::string& name);
    DynamicDataType(const std::string& name, DataTypeManager* dtm);
    DynamicDataType(const CategoryPath& path, const std::string& name);
    DynamicDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm);
    ~DynamicDataType() override = default;

    bool canSpecifyLength() override { return false; }

    int getNumComponents(MemBuffer* buf);
    DataTypeComponent* getComponent(int ordinal, MemBuffer* buf);
    std::vector<DataTypeComponent*> getComponents(MemBuffer* buf);

protected:
    std::vector<DataTypeComponent*> getComps(MemBuffer* buf);
    virtual std::vector<DataTypeComponent*> getAllComponents(MemBuffer* buf) = 0;

private:
    struct CacheEntry {
        std::vector<DataTypeComponent*> comps;
        std::vector<std::unique_ptr<DataTypeComponent>> ownedComps;
    };
    
    // Bounded cache to prevent unbounded growth for dynamic items
    std::unordered_map<uint64_t, std::unique_ptr<CacheEntry>> map_;
    void enforceCacheLimit();
};

} // namespace ghidra
