/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file FunctionManager.h
/// \brief Manager for functions in a program
/// Translated from: ghidra.program.model.listing.FunctionManager
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressHash.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/Variable.h>
#include <string>
#include <vector>
#include <set>
#include <unordered_map>
#include <memory>
#include <cstdint>

namespace ghidra {

class Program;
class Namespace;
class DataTypeManager;

class FunctionManager {
public:
    FunctionManager() = default;
    explicit FunctionManager(Program* program) : program_(program) {}

    Program* getProgram() const { return program_; }

    std::vector<std::string> getCallingConventionNames() const;

    PrototypeModel* getDefaultCallingConvention() const;

    PrototypeModel* getCallingConvention(const std::string& name) const;

    void addCallingConvention(const std::string& name, std::unique_ptr<PrototypeModel> model) {
        callingConventions_[name] = std::move(model);
    }

    Function* createFunction(const std::string& name, Address entryPoint,
                             const AddressSet& body, SourceType source);

    Function* createFunction(const std::string& name, Namespace* nameSpace,
                             Address entryPoint, const AddressSet& body, SourceType source);

    bool removeFunction(Address entryPoint);

    Function* getFunctionAt(Address entryPoint) const;

    Function* getFunctionContaining(Address addr) const;

    Function* getReferencedFunction(Address address) const;

    FunctionIterator getFunctions(bool forward = true) const;

    FunctionIterator getFunctions(Address start, bool forward = true) const;

    FunctionIterator getFunctions(const AddressSetView& asv, bool forward = true) const;

    bool isInFunction(Address addr) const;

    int getFunctionCount() const { return static_cast<int>(functions_.size()); }

    Function* getFunction(long key) const;

    Variable* getReferencedVariable(Address instrAddr, Address storageAddr,
                                     int size, bool isRead) const;

    void invalidateCache(bool all = true);

    void rebuildSortedFunctions() const;

    // Performance counters (reset before each analyzer)
    struct PerformanceCounters {
        int64_t getFunctionContaining_calls = 0;
        int64_t getFunctionAt_calls = 0;
        int64_t createFunction_calls = 0;
        void reset() { *this = PerformanceCounters{}; }
    };
    PerformanceCounters& getPerfCounters() const { return perfCounters_; }
    void resetPerfCounters() const { perfCounters_.reset(); }

private:
    Program* program_ = nullptr;
    std::unordered_map<uint64_t, std::unique_ptr<Function>, AddressHash> functions_;
    std::unordered_map<std::string, std::unique_ptr<PrototypeModel>> callingConventions_;
    std::string defaultCallingConventionName_;
    std::unordered_map<std::string, void*> cache_;

    // Sorted-by-entry-point function vector for O(log N) getFunctionContaining.
    // Rebuilt lazily when functions change.
    mutable std::vector<Function*> sortedFunctions_;
    mutable bool functionsDirty_ = true;
    // PHASE 10: std::set of body ranges for O(log N) overlap detection
    // and O(log N) insertion. Each range stored as a uint64_t pair.
    mutable std::set<std::pair<uint64_t, uint64_t>> sortedBodyRanges_;
    mutable PerformanceCounters perfCounters_;
};

} // namespace ghidra
