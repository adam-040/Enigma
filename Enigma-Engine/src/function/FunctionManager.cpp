/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionManager.cpp
/// \brief Implementation of FunctionManager
#include <ghidra/FunctionManager.h>
#include <algorithm>

namespace ghidra {

std::vector<std::string> FunctionManager::getCallingConventionNames() const {
    std::vector<std::string> names;
    for (const auto& pair : callingConventions_) {
        names.push_back(pair.first);
    }
    return names;
}

PrototypeModel* FunctionManager::getDefaultCallingConvention() const {
    if (defaultCallingConventionName_.empty()) return nullptr;
    auto it = callingConventions_.find(defaultCallingConventionName_);
    return (it != callingConventions_.end()) ? it->second.get() : nullptr;
}

PrototypeModel* FunctionManager::getCallingConvention(const std::string& name) const {
    auto it = callingConventions_.find(name);
    return (it != callingConventions_.end()) ? it->second.get() : nullptr;
}

Function* FunctionManager::createFunction(const std::string& name, Address entryPoint,
                                          const AddressSet& body, SourceType source) {
    std::string funcName = name;
    if (funcName.empty()) {
        funcName = "FUN_" + entryPoint.toString();
    }
    // Check for overlapping functions
    for (const auto& pair : functions_) {
        Function* existing = pair.second.get();
        if (existing->getBody().intersects(body)) {
            throw std::runtime_error("Function body overlaps existing function at " +
                                     existing->getEntryPoint().toString());
        }
    }
    auto func = std::make_unique<Function>(funcName, entryPoint, nullptr, source);
    func->setProgram(program_);
    func->setBody(body);
    Function* raw = func.get();
    functions_[entryPoint.toString()] = std::move(func);
    return raw;
}

Function* FunctionManager::createFunction(const std::string& name, Namespace* nameSpace,
                                          Address entryPoint, const AddressSet& body, SourceType source) {
    std::string funcName = name;
    if (funcName.empty()) {
        funcName = "FUN_" + entryPoint.toString();
    }
    // Check for overlapping functions
    for (const auto& pair : functions_) {
        Function* existing = pair.second.get();
        if (existing->getBody().intersects(body)) {
            throw std::runtime_error("Function body overlaps existing function at " +
                                     existing->getEntryPoint().toString());
        }
    }
    auto func = std::make_unique<Function>(funcName, entryPoint, nameSpace, source);
    func->setProgram(program_);
    func->setBody(body);
    Function* raw = func.get();
    functions_[entryPoint.toString()] = std::move(func);
    return raw;
}

bool FunctionManager::removeFunction(Address entryPoint) {
    return functions_.erase(entryPoint.toString()) > 0;
}

Function* FunctionManager::getFunctionAt(Address entryPoint) const {
    auto it = functions_.find(entryPoint.toString());
    return (it != functions_.end()) ? it->second.get() : nullptr;
}

Function* FunctionManager::getFunctionContaining(Address addr) const {
    for (const auto& pair : functions_) {
        Function* func = pair.second.get();
        if (func->getBody().contains(addr)) {
            return func;
        }
    }
    return nullptr;
}

Function* FunctionManager::getReferencedFunction(Address address) const {
    return getFunctionAt(address);
}

FunctionIterator FunctionManager::getFunctions(bool forward) const {
    std::vector<Function*> funcs;
    for (const auto& pair : functions_) {
        funcs.push_back(pair.second.get());
    }
    std::sort(funcs.begin(), funcs.end(), [](Function* a, Function* b) {
        return a->getEntryPoint() < b->getEntryPoint();
    });
    if (!forward) {
        std::reverse(funcs.begin(), funcs.end());
    }
    return FunctionIterator(funcs);
}

FunctionIterator FunctionManager::getFunctions(Address start, bool forward) const {
    std::vector<Function*> funcs;
    for (const auto& pair : functions_) {
        if (forward ? pair.second->getEntryPoint() >= start : pair.second->getEntryPoint() <= start) {
            funcs.push_back(pair.second.get());
        }
    }
    std::sort(funcs.begin(), funcs.end(), [forward](Function* a, Function* b) {
        return forward ? (a->getEntryPoint() < b->getEntryPoint())
                       : (a->getEntryPoint() > b->getEntryPoint());
    });
    return FunctionIterator(funcs);
}

FunctionIterator FunctionManager::getFunctions(const AddressSetView& asv, bool forward) const {
    std::vector<Function*> funcs;
    for (const auto& pair : functions_) {
        if (asv.contains(pair.second->getEntryPoint())) {
            funcs.push_back(pair.second.get());
        }
    }
    std::sort(funcs.begin(), funcs.end(), [](Function* a, Function* b) {
        return a->getEntryPoint() < b->getEntryPoint();
    });
    if (!forward) {
        std::reverse(funcs.begin(), funcs.end());
    }
    return FunctionIterator(funcs);
}

bool FunctionManager::isInFunction(Address addr) const {
    return getFunctionContaining(addr) != nullptr;
}

Function* FunctionManager::getFunction(long key) const {
    for (const auto& pair : functions_) {
        if (pair.second->getID() == key) {
            return pair.second.get();
        }
    }
    return nullptr;
}

Variable* FunctionManager::getReferencedVariable(Address instrAddr, Address storageAddr,
                                                  int size, bool isRead) const {
    Function* func = getFunctionContaining(instrAddr);
    if (!func) return nullptr;
    for (auto* var : func->getLocalVariables()) {
        if (var->getMinAddress() == storageAddr) return var;
    }
    return nullptr;
}

void FunctionManager::invalidateCache(bool all) {
    if (all) {
        cache_.clear();
    }
}

} // namespace ghidra
