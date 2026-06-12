#include <ghidra/Database.h>
#include <algorithm>

namespace ghidra {

Database::Database() : nextId(0) {}

int4 Database::addSymbol(const std::string& name, const Address& addr, uintb size, bool isLabel, bool isExternal) {
    int4 id = nextId++;
    SymbolEntry entry;
    entry.name = name;
    entry.address = addr;
    entry.size = size;
    entry.id = id;
    entry.isLabel = isLabel;
    entry.isExternal = isExternal;

    idMap[id] = entry;

    auto it = nameMap.find(name);
    if (it == nameMap.end()) {
        NameEntry ne;
        ne.name = name;
        ne.id = id;
        ne.entries.push_back(entry);
        nameMap[name] = ne;
    } else {
        it->second.entries.push_back(entry);
    }

    addressMap[addr].push_back(entry);
    return id;
}

bool Database::removeSymbol(int4 id) {
    auto it = idMap.find(id);
    if (it == idMap.end()) return false;

    SymbolEntry entry = it->second;
    idMap.erase(it);

    auto nit = nameMap.find(entry.name);
    if (nit != nameMap.end()) {
        auto& entries = nit->second.entries;
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [id](const SymbolEntry& e) { return e.id == id; }), entries.end());
        if (entries.empty()) {
            nameMap.erase(nit);
        }
    }

    auto ait = addressMap.find(entry.address);
    if (ait != addressMap.end()) {
        auto& entries = ait->second;
        entries.erase(std::remove_if(entries.begin(), entries.end(),
            [id](const SymbolEntry& e) { return e.id == id; }), entries.end());
        if (entries.empty()) {
            addressMap.erase(ait);
        }
    }

    return true;
}

bool Database::removeSymbolAt(const Address& addr) {
    auto it = addressMap.find(addr);
    if (it == addressMap.end()) return false;

    for (const auto& entry : it->second) {
        idMap.erase(entry.id);
        auto nit = nameMap.find(entry.name);
        if (nit != nameMap.end()) {
            auto& entries = nit->second.entries;
            entries.erase(std::remove_if(entries.begin(), entries.end(),
                [id = entry.id](const SymbolEntry& e) { return e.id == id; }), entries.end());
            if (entries.empty()) {
                nameMap.erase(nit);
            }
        }
    }

    addressMap.erase(it);
    return true;
}

Database::SymbolEntry* Database::getSymbol(int4 id) {
    auto it = idMap.find(id);
    return (it != idMap.end()) ? &it->second : nullptr;
}

const Database::SymbolEntry* Database::getSymbol(int4 id) const {
    auto it = idMap.find(id);
    return (it != idMap.end()) ? &it->second : nullptr;
}

Database::SymbolEntry* Database::getSymbol(const std::string& name, const Address& addr) {
    auto nit = nameMap.find(name);
    if (nit == nameMap.end()) return nullptr;

    for (auto& entry : nit->second.entries) {
        if (entry.address == addr) return &entry;
    }
    return nullptr;
}

const Database::SymbolEntry* Database::getSymbol(const std::string& name, const Address& addr) const {
    auto nit = nameMap.find(name);
    if (nit == nameMap.end()) return nullptr;

    for (const auto& entry : nit->second.entries) {
        if (entry.address == addr) return &entry;
    }
    return nullptr;
}

std::vector<Database::SymbolEntry*> Database::getSymbolsAt(const Address& addr) {
    std::vector<SymbolEntry*> result;
    auto it = addressMap.find(addr);
    if (it != addressMap.end()) {
        for (auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<const Database::SymbolEntry*> Database::getSymbolsAt(const Address& addr) const {
    std::vector<const SymbolEntry*> result;
    auto it = addressMap.find(addr);
    if (it != addressMap.end()) {
        for (const auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<Database::SymbolEntry*> Database::getSymbolsByName(const std::string& name) {
    std::vector<SymbolEntry*> result;
    auto it = nameMap.find(name);
    if (it != nameMap.end()) {
        for (auto& entry : it->second.entries) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<const Database::SymbolEntry*> Database::getSymbolsByName(const std::string& name) const {
    std::vector<const SymbolEntry*> result;
    auto it = nameMap.find(name);
    if (it != nameMap.end()) {
        for (const auto& entry : it->second.entries) {
            result.push_back(&entry);
        }
    }
    return result;
}

Address Database::queryAddress(const Address& addr) const {
    auto it = addressMap.lower_bound(addr);
    if (it != addressMap.end() && it->first == addr) {
        return it->first;
    }
    if (it != addressMap.begin()) {
        --it;
        return it->first;
    }
    return Address::NO_ADDRESS;
}

Cover Database::queryCover(const Address& startAddr, const Address& endAddr, bool intersect) const {
    Cover result;
    for (const auto& pair : addressMap) {
        const Address& addr = pair.first;
        if (intersect) {
            if (addr >= startAddr && addr <= endAddr) {
                result.addRange(addr, addr);
            }
        } else {
            result.addRange(addr, addr);
        }
    }
    return result;
}

void Database::clear() {
    nameMap.clear();
    idMap.clear();
    addressMap.clear();
    nextId = 0;
}

void Database::setAttribute(int4 id, bool isLabel, bool isExternal) {
    auto it = idMap.find(id);
    if (it != idMap.end()) {
        it->second.isLabel = isLabel;
        it->second.isExternal = isExternal;
    }
}

} // namespace ghidra
