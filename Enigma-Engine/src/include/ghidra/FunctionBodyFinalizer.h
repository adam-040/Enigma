#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>
#include <vector>
#include <string>

namespace ghidra {

class Program;
class FunctionManager;
class Listing;
class TaskMonitor;
class MessageLog;

class FunctionBodyFinalizer : public AbstractAnalyzer {
public:
    FunctionBodyFinalizer();
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
    bool canAnalyze(Program* program) const override;

private:
    uint64_t findFunctionEnd(Listing* listing, uint64_t entryAddr, uint64_t nextFuncAddr) const;

    static constexpr uint64_t kMaxScanBytes = 512;
    static constexpr uint64_t kMaxInstructions = 100;
};

} // namespace ghidra