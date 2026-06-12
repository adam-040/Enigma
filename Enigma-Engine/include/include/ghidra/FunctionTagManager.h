#pragma once

#include <ghidra/FunctionTag.h>
#include <vector>
#include <string>

namespace ghidra {

class FunctionTagManager {
public:
    virtual ~FunctionTagManager() = default;

    virtual FunctionTag* getFunctionTag(const std::string& name) = 0;
    virtual FunctionTag* getFunctionTag(long id) = 0;
    virtual std::vector<FunctionTag*> getAllFunctionTags() = 0;
    virtual bool isTagAssigned(const std::string& name) = 0;
    virtual FunctionTag* createFunctionTag(const std::string& name, const std::string& comment) = 0;
    virtual int getUseCount(FunctionTag* tag) = 0;
    virtual void removeFunctionTag(long id) = 0;
};

} // namespace ghidra
