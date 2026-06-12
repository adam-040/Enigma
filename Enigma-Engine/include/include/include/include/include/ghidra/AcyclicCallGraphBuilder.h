/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AcyclicCallGraphBuilder.h
/// \brief Build a DependencyGraph from a program's acyclic function call graph
/// Translated from: ghidra.program.model.util.AcyclicCallGraphBuilder
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/DependencyGraph.h>
#include <ghidra/Function.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>
#include <set>
#include <deque>
#include <vector>
#include <memory>

namespace ghidra {

class Program;
class ReferenceManager;
class FunctionManager;

class AcyclicCallGraphBuilder {
public:
    AcyclicCallGraphBuilder(Program* program, bool killThunks);

    AcyclicCallGraphBuilder(Program* program, const AddressSetView& set, bool killThunks);

    AcyclicCallGraphBuilder(Program* program, const std::vector<Function*>& functions,
                            bool killThunks);

    std::unique_ptr<DependencyGraph<Address>> getDependencyGraph(TaskMonitor& monitor);

private:
    struct StackNode {
        Address address;
        std::vector<Address> children;
        size_t nextchild = 0;

        std::string toString() const {
            std::string s = address.toString();
            s += children.empty() ? " <no children>" : " " + std::to_string(children.size()) + " children";
            return s;
        }
    };

    struct VisitStack {
        std::set<Address> inStack;
        std::deque<StackNode> stack;

        VisitStack(const Address& functionEntry);

        bool isEmpty() const;
        StackNode& peek();
        bool contains(const Address& address) const;
        void push(const Address& address);
        void pop();
    };

    static std::set<Address> findFunctions(Program* program, const AddressSetView& set,
                                           bool killThunks);

    std::deque<Address> findStartPoints();

    Address getNextStartFunction(std::deque<Address>& startPoints,
                                 std::set<Address>& unProcessedSet);

    bool isStartFunction(const Address& address) const;

    void initializeNode(StackNode& node);

    void processForward(DependencyGraph<Address>& graph, std::set<Address>& unprocessed,
                        const Address& startFunction, TaskMonitor& monitor);

    Program* program_;
    std::set<Address> functionSet_;
    bool killThunks_;
};

} // namespace ghidra
