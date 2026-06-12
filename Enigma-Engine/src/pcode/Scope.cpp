#include <ghidra/Scope.h>
#include <algorithm>
#include <sstream>

namespace ghidra {

Scope::Scope(const std::string& nm, int4 prio, bool global)
    : name(nm), nextId(0), priority(prio), isGlobal(global) {
}

int4 Scope::addSymbol(const std::string& name, const Address& addr, uintb size, DataType* type,
                      bool isLabel, bool isExternal, bool isDynamic) {
    int4 id = nextId++;
    SymbolEntry entry;
    entry.name = name;
    entry.address = addr;
    entry.size = size;
    entry.type = type;
    entry.id = id;
    entry.isLabel = isLabel;
    entry.isExternal = isExternal;
    entry.isDynamic = isDynamic;

    idMap[id] = entry;

    auto it = nameMap.find(name);
    if (it == nameMap.end()) {
        std::vector<SymbolEntry> entries;
        entries.push_back(entry);
        nameMap[name] = entries;
    } else {
        it->second.push_back(entry);
    }

    addressMap[addr].push_back(entry);
    return id;
}

bool Scope::removeSymbol(int4 id) {
    auto it = idMap.find(id);
    if (it == idMap.end()) return false;

    SymbolEntry entry = it->second;
    idMap.erase(it);

    auto nit = nameMap.find(entry.name);
    if (nit != nameMap.end()) {
        auto& entries = nit->second;
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

bool Scope::removeSymbolAt(const Address& addr) {
    auto it = addressMap.find(addr);
    if (it == addressMap.end()) return false;

    for (const auto& entry : it->second) {
        idMap.erase(entry.id);
        auto nit = nameMap.find(entry.name);
        if (nit != nameMap.end()) {
            auto& entries = nit->second;
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

Scope::SymbolEntry* Scope::getSymbol(int4 id) {
    auto it = idMap.find(id);
    return (it != idMap.end()) ? &it->second : nullptr;
}

const Scope::SymbolEntry* Scope::getSymbol(int4 id) const {
    auto it = idMap.find(id);
    return (it != idMap.end()) ? &it->second : nullptr;
}

Scope::SymbolEntry* Scope::getSymbol(const std::string& name, const Address& addr) {
    auto nit = nameMap.find(name);
    if (nit == nameMap.end()) return nullptr;

    for (auto& entry : nit->second) {
        if (entry.address == addr) return &entry;
    }
    return nullptr;
}

const Scope::SymbolEntry* Scope::getSymbol(const std::string& name, const Address& addr) const {
    auto nit = nameMap.find(name);
    if (nit == nameMap.end()) return nullptr;

    for (const auto& entry : nit->second) {
        if (entry.address == addr) return &entry;
    }
    return nullptr;
}

std::vector<Scope::SymbolEntry*> Scope::getSymbolsAt(const Address& addr) {
    std::vector<SymbolEntry*> result;
    auto it = addressMap.find(addr);
    if (it != addressMap.end()) {
        for (auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<const Scope::SymbolEntry*> Scope::getSymbolsAt(const Address& addr) const {
    std::vector<const SymbolEntry*> result;
    auto it = addressMap.find(addr);
    if (it != addressMap.end()) {
        for (const auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<Scope::SymbolEntry*> Scope::getSymbolsByName(const std::string& name) {
    std::vector<SymbolEntry*> result;
    auto it = nameMap.find(name);
    if (it != nameMap.end()) {
        for (auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

std::vector<const Scope::SymbolEntry*> Scope::getSymbolsByName(const std::string& name) const {
    std::vector<const SymbolEntry*> result;
    auto it = nameMap.find(name);
    if (it != nameMap.end()) {
        for (const auto& entry : it->second) {
            result.push_back(&entry);
        }
    }
    return result;
}

Scope::SymbolEntry* Scope::queryAddress(const Address& addr) {
    auto it = addressMap.find(addr);
    if (it != addressMap.end() && !it->second.empty()) {
        return &it->second[0];
    }
    return nullptr;
}

const Scope::SymbolEntry* Scope::queryAddress(const Address& addr) const {
    auto it = addressMap.find(addr);
    if (it != addressMap.end() && !it->second.empty()) {
        return &it->second[0];
    }
    return nullptr;
}

void Scope::addRange(const Address& first, const Address& last, int4 prio) {
    Range range;
    range.firstAddr = first;
    range.lastAddr = last;
    range.priority = prio;
    ranges.push_back(range);
}

bool Scope::inRange(const Address& addr) const {
    for (const auto& r : ranges) {
        if (addr >= r.firstAddr && addr <= r.lastAddr) return true;
    }
    return false;
}

void Scope::clear() {
    nameMap.clear();
    idMap.clear();
    addressMap.clear();
    ranges.clear();
    nextId = 0;
}

void Scope::saveXml(std::string& output) const {
    output += "<scope name=\"" + name + "\" priority=\"" + std::to_string(priority) + "\">\n";
    for (const auto& pair : idMap) {
        const auto& entry = pair.second;
        output += "  <symbol name=\"" + entry.name + "\"";
        output += " address=\"" + entry.address.toString() + "\"";
        output += " size=\"" + entry.size.str() + "\"";
        output += " id=\"" + std::to_string(entry.id) + "\"";
        if (entry.isLabel) output += " label=\"true\"";
        if (entry.isExternal) output += " external=\"true\"";
        output += "/>\n";
    }
    output += "</scope>\n";
}

void Scope::restoreXml(const std::string& input) {
    (void)input;
}

ScopeInternal::ScopeInternal(const std::string& nm, int4 prio, bool global, TypeFactory* tf)
    : Scope(nm, prio, global), typeFactory(tf) {
}

void ScopeInternal::saveXml(std::string& output) const {
    Scope::saveXml(output);
}

void ScopeInternal::restoreXml(const std::string& input) {
    Scope::restoreXml(input);
}

ScopeLocal::ScopeLocal(const std::string& nm, int4 prio, bool global, TypeFactory* tf)
    : ScopeInternal(nm, prio, global, tf) {
}

ScopeGhidra::ScopeGhidra(const std::string& nm, int4 prio, bool global, Database* db)
    : Scope(nm, prio, global), database(db) {
}

} // namespace ghidra
