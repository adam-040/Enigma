#include <ghidra/DynamicDataType.h>

namespace ghidra {

DynamicDataType::DynamicDataType(const std::string& name)
    : BuiltIn(CategoryPath::ROOT(), name, nullptr) {}

DynamicDataType::DynamicDataType(const std::string& name, DataTypeManager* dtm)
    : BuiltIn(CategoryPath::ROOT(), name, dtm) {}

DynamicDataType::DynamicDataType(const CategoryPath& path, const std::string& name)
    : BuiltIn(path, name, nullptr) {}

DynamicDataType::DynamicDataType(const CategoryPath& path, const std::string& name, DataTypeManager* dtm)
    : BuiltIn(path, name, dtm) {}

int DynamicDataType::getNumComponents(MemBuffer* buf) {
    auto comps = getComps(buf);
    if (comps.empty()) {
        return -1;
    }
    return static_cast<int>(comps.size());
}

DataTypeComponent* DynamicDataType::getComponent(int ordinal, MemBuffer* buf) {
    auto comps = getComps(buf);
    if (!comps.empty() && ordinal >= 0 && ordinal < static_cast<int>(comps.size())) {
        return comps[ordinal];
    }
    return nullptr;
}

std::vector<DataTypeComponent*> DynamicDataType::getComponents(MemBuffer* buf) {
    return getComps(buf);
}

std::vector<DataTypeComponent*> DynamicDataType::getComps(MemBuffer* buf) {
    if (!buf) return {};
    
    Address addr = buf->getAddress();
    uint64_t key = addr.getOffset(); // Simplify by using flat offset for LRU
    
    auto it = map_.find(key);
    if (it != map_.end()) {
        return it->second->comps;
    }
    
    auto comps = getAllComponents(buf);
    if (comps.empty()) {
        return comps;
    }
    
    auto entry = std::make_unique<CacheEntry>();
    entry->comps = comps;
    // Currently, if getAllComponents returns newly allocated components, it's expected
    // to pass ownership if needed, but the interface usually implies the DataType owns them.
    // In Java, DataTypeComponent[] was stored directly.
    map_[key] = std::move(entry);
    enforceCacheLimit();
    
    return map_[key]->comps;
}

void DynamicDataType::enforceCacheLimit() {
    if (map_.size() > 100) {
        // Clear randomly or simply clear all if it gets too large
        map_.clear();
    }
}

} // namespace ghidra
