/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AcyclicCallGraphBuilder.cpp
/// \brief Implementation of AcyclicCallGraphBuilder
#include "ghidra/AcyclicCallGraphBuilder.h"
#include "ghidra/Program.h"
#include "ghidra/ReferenceManager.h"
#include "ghidra/FunctionManager.h"
#include "ghidra/RefType.h"
#include "ghidra/AddressIterator.h"
#include <stdexcept>

namespace ghidra {

AcyclicCallGraphBuilder::AcyclicCallGraphBuilder(Program* program, bool killThunks)
    : program_(program), killThunks_(killThunks) {
    auto* funcMgr = program_->getFunctionManager();
    auto funcIter = funcMgr->getFunctions(true);
    while (funcIter.hasNext()) {
        auto* function = funcIter.next();
        if (killThunks_ && function->isThunk()) {
            function = function->getThunkedFunction();
        }
        functionSet_.insert(function->getEntryPoint());
    }
}

AcyclicCallGraphBuilder::AcyclicCallGraphBuilder(Program* program, const AddressSetView& set,
                                                 bool killThunks)
    : program_(program),
      functionSet_(findFunctions(program, set, killThunks)),
      killThunks_(killThunks) {
}

AcyclicCallGraphBuilder::AcyclicCallGraphBuilder(Program* program,
                                                 const std::vector<Function*>& functions,
                                                 bool killThunks)
    : program_(program), killThunks_(killThunks) {
    for (auto* function : functions) {
        if (killThunks_) {
            if (function->isThunk()) {
                function = function->getThunkedFunction();
            }
        }
        functionSet_.insert(function->getEntryPoint());
    }
}

std::unique_ptr<DependencyGraph<Address>> AcyclicCallGraphBuilder::getDependencyGraph(
        TaskMonitor& monitor) {
    auto graph = std::make_unique<DependencyGraph<Address>>();
    auto startPoints = findStartPoints();
    std::set<Address> unprocessed(functionSet_.begin(), functionSet_.end());
    monitor.initialize(static_cast<int64_t>(unprocessed.size()));

    while (!unprocessed.empty()) {
        monitor.checkCancelled();
        Address functionEntry = getNextStartFunction(startPoints, unprocessed);
        processForward(*graph, unprocessed, functionEntry, monitor);
    }

    return graph;
}

Address AcyclicCallGraphBuilder::getNextStartFunction(std::deque<Address>& startPoints,
                                                      std::set<Address>& unProcessedSet) {
    while (!startPoints.empty()) {
        Address address = startPoints.front();
        startPoints.pop_front();
        if (unProcessedSet.find(address) != unProcessedSet.end()) {
            return address;
        }
    }
    return *unProcessedSet.begin();
}

std::deque<Address> AcyclicCallGraphBuilder::findStartPoints() {
    std::deque<Address> startPoints;
    for (const auto& address : functionSet_) {
        if (isStartFunction(address)) {
            startPoints.push_back(address);
        }
    }
    return startPoints;
}

void AcyclicCallGraphBuilder::initializeNode(StackNode& node) {
    auto* fmanage = program_->getFunctionManager();
    auto* function = fmanage->getFunctionAt(node.address);
    if (function->isThunk()) {
        auto* thunkedfunc = function->getThunkedFunction();
        node.children = { thunkedfunc->getEntryPoint() };
        return;
    }

    std::vector<Address> children;
    auto* refManager = program_->getReferenceManager();
    auto refSourceIter = refManager->getReferenceSourceIterator(function->getBody(), true);

    while (refSourceIter->hasNext()) {
        Address fromAddr = refSourceIter->next();
        for (auto* ref : refManager->getFlowReferencesFrom(fromAddr)) {
            Address toAddr = ref->getToAddress();
            if (ref->getReferenceType()->isCall()) {
                auto* childfunc = fmanage->getFunctionAt(toAddr);
                if (childfunc != nullptr && killThunks_) {
                    if (childfunc->isThunk()) {
                        childfunc = childfunc->getThunkedFunction();
                        toAddr = childfunc->getEntryPoint();
                    }
                }
                if (functionSet_.find(toAddr) != functionSet_.end()) {
                    children.push_back(toAddr);
                }
            }
        }
    }
    node.children = std::move(children);
}

void AcyclicCallGraphBuilder::processForward(DependencyGraph<Address>& graph,
                                             std::set<Address>& unprocessed,
                                             const Address& startFunction, TaskMonitor& monitor) {
    VisitStack stack(startFunction);
    StackNode* curnode = &stack.peek();
    initializeNode(*curnode);
    graph.addValue(curnode->address);

    while (!stack.isEmpty()) {
        monitor.checkCancelled();

        curnode = &stack.peek();
        if (curnode->nextchild >= curnode->children.size()) {
            unprocessed.erase(curnode->address);
            monitor.incrementProgress(1);
            stack.pop();
        } else {
            Address childAddr = curnode->children[curnode->nextchild++];
            if (!stack.contains(childAddr)) {
                if (unprocessed.find(childAddr) != unprocessed.end()) {
                    stack.push(childAddr);
                    StackNode* nextnode = &stack.peek();
                    initializeNode(*nextnode);
                    childAddr = nextnode->address;
                    graph.addValue(nextnode->address);
                }
                graph.addDependency(curnode->address, childAddr);
            }
        }
    }
}

bool AcyclicCallGraphBuilder::isStartFunction(const Address& address) const {
    auto* refManager = program_->getReferenceManager();
    auto referencesTo = refManager->getReferencesTo(address);

    for (auto* ref : referencesTo) {
        if (ref->isEntryPointReference()) {
            return true;
        }
        if (ref->getReferenceType()->isCall()) {
            return false;
        }
    }
    return true;
}

std::set<Address> AcyclicCallGraphBuilder::findFunctions(Program* program,
                                                         const AddressSetView& set,
                                                         bool killThunks) {
    std::set<Address> functionStarts;
    auto funcIter = program->getFunctionManager()->getFunctions(set, true);
    while (funcIter.hasNext()) {
        auto* function = funcIter.next();
        if (killThunks) {
            if (function->isThunk()) {
                function = function->getThunkedFunction();
            }
        }
        functionStarts.insert(function->getEntryPoint());
    }
    return functionStarts;
}

AcyclicCallGraphBuilder::VisitStack::VisitStack(const Address& functionEntry) {
    push(functionEntry);
}

bool AcyclicCallGraphBuilder::VisitStack::isEmpty() const {
    return stack.empty();
}

AcyclicCallGraphBuilder::StackNode& AcyclicCallGraphBuilder::VisitStack::peek() {
    return stack.front();
}

bool AcyclicCallGraphBuilder::VisitStack::contains(const Address& address) const {
    return inStack.find(address) != inStack.end();
}

void AcyclicCallGraphBuilder::VisitStack::push(const Address& address) {
    if (!inStack.insert(address).second) {
        throw std::runtime_error("Attempted to visit an address that is already on the stack");
    }
    StackNode newnode;
    newnode.address = address;
    newnode.nextchild = 0;
    stack.push_front(std::move(newnode));
}

void AcyclicCallGraphBuilder::VisitStack::pop() {
    Address address = stack.front().address;
    stack.pop_front();
    inStack.erase(address);
}

} // namespace ghidra
