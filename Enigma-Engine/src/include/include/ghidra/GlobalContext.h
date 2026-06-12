#pragma once

#include <ghidra/Address.h>
#include <string>
#include <ghidra/Types.h>
#include <map>
#include <vector>

namespace ghidra {

class GlobalContext {
public:
    struct ContextRegister {
        std::string name;
        int4 startBit;
        int4 numBits;
        uintb defaultValue;
        uintb currentValue;
        uintb mask;
    };

    struct ContextChange {
        Address startAddr;
        Address endAddr;
        std::string registerName;
        uintb value;
    };

private:
    std::map<std::string, ContextRegister> registers;
    std::vector<ContextChange> changes;
    Address currentAddr;
    bool allowSet;

public:
    GlobalContext();
    ~GlobalContext() = default;

    void addRegister(const std::string& name, int4 startBit, int4 numBits, uintb defaultValue = 0);
    void setDefaultValue(const std::string& name, uintb value);
    uintb getDefaultValue(const std::string& name) const;

    void setCurrentAddress(const Address& addr);
    const Address& getCurrentAddress() const { return currentAddr; }

    void setContext(const Address& startAddr, const Address& endAddr, const std::string& name, uintb value);
    uintb getContext(const Address& addr, const std::string& name) const;
    uintb getContext(const std::string& name) const;

    bool hasRegister(const std::string& name) const;
    int4 getRegisterSize(const std::string& name) const;
    int4 getRegisterStartBit(const std::string& name) const;

    void setAllowSet(bool val) { allowSet = val; }
    bool isAllowSet() const { return allowSet; }

    int4 getNumRegisters() const { return static_cast<int4>(registers.size()); }
    int4 getNumChanges() const { return static_cast<int4>(changes.size()); }
    const ContextChange& getChange(int4 index) const { return changes.at(index); }

    void clear();
    void clearChanges();
    void resetToDefaults();
};

} // namespace ghidra
