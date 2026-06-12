#pragma once

#include <ghidra/Program.h>
#include <ghidra/Address.h>
#include <ghidra/TaskMonitor.h>
#include <string>
#include <memory>
#include <vector>

namespace ghidra {

class Function;

struct DecompiledCall {
    Address entryAddress;
    std::string name;
    int stackPurgeSize;
};

struct DecompFunctionSummary {
    Address entryAddress;
    std::string name;
    int bodyAddressCount = 0;
    bool external = false;
    bool thunk = false;
};

class DecompileResults {
public:
    bool decompiled;
    Address entryPoint;
    std::string functionName;
    int functionSize;
    int stackPurgeSize;
    std::string conventionName;
    std::string cCode;
    std::vector<DecompiledCall> calls;
    int callCount;

    DecompileResults();
};

class DecompInterface {
public:
    DecompInterface();
    ~DecompInterface();

    bool openProgram(Program* program);
    void closeProgram();
    bool isOpen() const;

    std::vector<DecompFunctionSummary> getFunctions() const;
    DecompileResults decompileFunction(const Address& entryPoint, TaskMonitor* monitor);
    DecompileResults decompileFunction(Function* function, TaskMonitor* monitor);

    static bool initializeLibrary();
    static void shutdownLibrary();

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace ghidra
