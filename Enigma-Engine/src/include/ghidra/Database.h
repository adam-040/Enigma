#pragma once

#include <ghidra/Address.h>
#include <ghidra/Cover.h>
#include <string>
#include <vector>
#include <ghidra/Types.h>
#include <map>

namespace ghidra {

class Database {
public:
    struct SymbolEntry {
        std::string name;
        Address address;
        uintb size;
        int4 id;
        bool isLabel;
        bool isExternal;
    };

    struct NameEntry {
        std::string name;
        int4 id;
        std::vector<SymbolEntry> entries;
    };

private:
    std::map<std::string, NameEntry> nameMap;
    std::map<int4, SymbolEntry> idMap;
    std::map<Address, std::vector<SymbolEntry>> addressMap;
    int4 nextId;

public:
    Database();
    ~Database() = default;

    int4 addSymbol(const std::string& name, const Address& addr, uintb size, bool isLabel = false, bool isExternal = false);
    bool removeSymbol(int4 id);
    bool removeSymbolAt(const Address& addr);

    SymbolEntry* getSymbol(int4 id);
    const SymbolEntry* getSymbol(int4 id) const;
    SymbolEntry* getSymbol(const std::string& name, const Address& addr);
    const SymbolEntry* getSymbol(const std::string& name, const Address& addr) const;

    std::vector<SymbolEntry*> getSymbolsAt(const Address& addr);
    std::vector<const SymbolEntry*> getSymbolsAt(const Address& addr) const;
    std::vector<SymbolEntry*> getSymbolsByName(const std::string& name);
    std::vector<const SymbolEntry*> getSymbolsByName(const std::string& name) const;

    Address queryAddress(const Address& addr) const;
    Cover queryCover(const Address& startAddr, const Address& endAddr, bool intersect) const;

    int4 getNumSymbols() const { return static_cast<int4>(idMap.size()); }
    int4 getNextId() const { return nextId; }

    void clear();
    void setAttribute(int4 id, bool isLabel, bool isExternal);
};

} // namespace ghidra
