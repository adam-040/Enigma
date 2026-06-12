#pragma once

#include <ghidra/Address.h>
#include <ghidra/Database.h>
#include <ghidra/TypeFactory.h>
#include <string>
#include <vector>
#include <ghidra/Types.h>
#include <map>

namespace ghidra {

class Funcdata;

class Scope {
public:
    struct SymbolEntry {
        std::string name;
        Address address;
        uintb size;
        DataType* type;
        int4 id;
        bool isLabel;
        bool isExternal;
        bool isDynamic;
    };

    struct Range {
        Address firstAddr;
        Address lastAddr;
        int4 priority;
    };

protected:
    std::string name;
    std::map<std::string, std::vector<SymbolEntry>> nameMap;
    std::map<int4, SymbolEntry> idMap;
    std::map<Address, std::vector<SymbolEntry>> addressMap;
    std::vector<Range> ranges;
    int4 nextId;
    int4 priority;
    bool isGlobal;

public:
    Scope(const std::string& nm, int4 prio, bool global);
    virtual ~Scope() = default;

    virtual int4 addSymbol(const std::string& name, const Address& addr, uintb size, DataType* type,
                           bool isLabel = false, bool isExternal = false, bool isDynamic = false);
    virtual bool removeSymbol(int4 id);
    virtual bool removeSymbolAt(const Address& addr);

    SymbolEntry* getSymbol(int4 id);
    const SymbolEntry* getSymbol(int4 id) const;
    SymbolEntry* getSymbol(const std::string& name, const Address& addr);
    const SymbolEntry* getSymbol(const std::string& name, const Address& addr) const;

    std::vector<SymbolEntry*> getSymbolsAt(const Address& addr);
    std::vector<const SymbolEntry*> getSymbolsAt(const Address& addr) const;
    std::vector<SymbolEntry*> getSymbolsByName(const std::string& name);
    std::vector<const SymbolEntry*> getSymbolsByName(const std::string& name) const;

    virtual SymbolEntry* queryAddress(const Address& addr);
    virtual const SymbolEntry* queryAddress(const Address& addr) const;

    void addRange(const Address& first, const Address& last, int4 prio);
    bool inRange(const Address& addr) const;

    const std::string& getName() const { return name; }
    int4 getPriority() const { return priority; }
    bool isGlobalScope() const { return isGlobal; }
    int4 getNumSymbols() const { return static_cast<int4>(idMap.size()); }
    int4 getNextId() const { return nextId; }

    virtual void clear();
    virtual void saveXml(std::string& output) const;
    virtual void restoreXml(const std::string& input);
};

class ScopeInternal : public Scope {
private:
    TypeFactory* typeFactory;

public:
    ScopeInternal(const std::string& nm, int4 prio, bool global, TypeFactory* tf);
    ~ScopeInternal() override = default;

    TypeFactory* getTypeFactory() const { return typeFactory; }

    void saveXml(std::string& output) const override;
    void restoreXml(const std::string& input) override;
};

class ScopeLocal : public ScopeInternal {
public:
    ScopeLocal(const std::string& nm, int4 prio, bool global, TypeFactory* tf);
    ~ScopeLocal() override = default;
};

class ScopeGhidra : public Scope {
private:
    Database* database;

public:
    ScopeGhidra(const std::string& nm, int4 prio, bool global, Database* db);
    ~ScopeGhidra() override = default;

    Database* getDatabase() const { return database; }
};

} // namespace ghidra
