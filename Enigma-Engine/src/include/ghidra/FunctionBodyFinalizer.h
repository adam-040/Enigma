#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>

namespace ghidra {

class Program;
class TaskMonitor;
class MessageLog;

class FunctionBodyFinalizer : public AbstractAnalyzer {
public:
    FunctionBodyFinalizer();
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
    bool canAnalyze(Program* program) const override;
};

} // namespace ghidra