#pragma once

#include <ghidra/Program.h>
#include <ghidra/Address.h>
#include <vector>

namespace ghidra {

class TaskMonitor;

class MySwitchAnalyzer {
public:
    explicit MySwitchAnalyzer(Program* program);

    static bool analyze(Program* program, const Address& functionEntry, TaskMonitor* monitor);

    bool resolvedFlow(const Address& flowFrom, const Address& destAddr, TaskMonitor* monitor);
    std::vector<Address> unresolvedIndirectFlow(const Address& instrAddr,
                                                  uint64_t destination, int entrySize,
                                                  TaskMonitor* monitor);

private:
    Program* program_;

    std::vector<Address> handleOffsetSwitch(const Address& instrAddr, uint64_t destValue,
                                              int entrySize, TaskMonitor* monitor);
    void addReference(const Address& flowFrom, const Address& toAddr);
};

} // namespace ghidra
