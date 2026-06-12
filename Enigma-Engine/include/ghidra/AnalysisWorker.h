#pragma once

#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <string>

namespace ghidra {

class AnalysisWorker {
public:
    virtual ~AnalysisWorker() = default;

    virtual bool analysisWorkerCallback(Program* program, void* workerContext, TaskMonitor* monitor) = 0;
    virtual std::string getWorkerName() const = 0;
};

} // namespace ghidra
