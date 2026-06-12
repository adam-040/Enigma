#pragma once

#include <ghidra/Address.h>
#include <ghidra/Types.h>
#include <map>
#include <string>
#include <vector>

namespace ghidra {

class ContextDatabase {
public:
    struct ContextEntry {
        std::string name;
        uintb value;
        uintb mask;
        int4 numBits;
        int4 startBit;
    };

    struct ContextRange {
        Address startAddr;
        Address endAddr;
        std::map<std::string, uintb> values;
    };

private:
    std::map<std::string, ContextEntry> contextNames;
    std::vector<ContextRange> ranges;
    std::map<std::string, uintb> defaultValues;

public:
    ContextDatabase() = default;
    ~ContextDatabase() = default;

    void addContext(const std::string& name, int4 startBit, int4 numBits);
    void setDefault(const std::string& name, uintb value);
    uintb getDefaultValue(const std::string& name) const;

    void setContext(const Address& startAddr, const Address& endAddr, const std::string& name, uintb value);
    uintb getContext(const Address& addr, const std::string& name) const;

    bool hasContext(const std::string& name) const;
    int4 getContextSize(const std::string& name) const;
    int4 getContextStartBit(const std::string& name) const;

    int4 getNumRanges() const { return static_cast<int4>(ranges.size()); }
    const ContextRange& getRange(int4 i) const { return ranges.at(i); }

    void clear();
};

} // namespace ghidra
