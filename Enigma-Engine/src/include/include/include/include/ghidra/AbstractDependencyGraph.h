/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file AbstractDependencyGraph.h
/// \brief Template base class for managing acyclic dependency graphs
/// Translated from: ghidra.util.graph.AbstractDependencyGraph
#pragma once

#include <set>
#include <unordered_map>
#include <memory>
#include <stdexcept>
#include <iostream>

namespace ghidra {

template<typename T>
class AbstractDependencyGraph {
protected:
    struct DependencyNode {
        T value;
        std::set<DependencyNode*> nodesThatDependOnMe;
        int numberOfNodesThatIDependOn = 0;

        DependencyNode(const T& val) : value(val) {}
    };

    std::unordered_map<T, std::unique_ptr<DependencyNode>> nodeMap;
    std::set<T> unvisitedIndependentSet;
    int visitedButNotDeletedCount = 0;

    virtual std::unique_ptr<std::unordered_map<T, std::unique_ptr<DependencyNode>>> createNodeMap() = 0;
    virtual std::unique_ptr<std::set<T>> createNodeSet() = 0;
    virtual std::unique_ptr<std::set<DependencyNode*>> createDependencyNodeSet() = 0;

    DependencyNode* getOrCreateDependencyNode(const T& value) {
        auto it = nodeMap.find(value);
        if (it == nodeMap.end()) {
            auto node = std::make_unique<DependencyNode>(value);
            auto* raw = node.get();
            nodeMap[value] = std::move(node);
            unvisitedIndependentSet.insert(value);
            return raw;
        }
        return it->second.get();
    }

    void checkCycleState() {
        if (!isEmpty() && unvisitedIndependentSet.empty() && visitedButNotDeletedCount == 0) {
            throw std::runtime_error("Cycle detected!");
        }
    }

    void reset() {
        visitedButNotDeletedCount = 0;
        for (auto& kv : nodeMap) {
            kv.second->numberOfNodesThatIDependOn = 0;
        }
        unvisitedIndependentSet.clear();
        for (auto& kv : nodeMap) {
            auto* node = kv.second.get();
            if (!node->nodesThatDependOnMe.empty()) {
                for (auto* child : node->nodesThatDependOnMe) {
                    unvisitedIndependentSet.erase(child->value);
                    child->numberOfNodesThatIDependOn++;
                }
            }
        }
        unvisitedIndependentSet = getAllIndependentValues();
    }

public:
    AbstractDependencyGraph() {
        nodeMap.clear();
        unvisitedIndependentSet.clear();
    }

    virtual ~AbstractDependencyGraph() = default;

    virtual AbstractDependencyGraph* copy() const = 0;

    void addValue(const T& value) {
        getOrCreateDependencyNode(value);
    }

    int size() const {
        return static_cast<int>(nodeMap.size());
    }

    bool isEmpty() const {
        return nodeMap.empty();
    }

    bool contains(const T& value) const {
        return nodeMap.find(value) != nodeMap.end();
    }

    std::set<T> getValues() const {
        std::set<T> result;
        for (const auto& kv : nodeMap) {
            result.insert(kv.first);
        }
        return result;
    }

    virtual std::set<T> getNodeMapValues() = 0;

    void addDependency(const T& value1, const T& value2) {
        auto* node1 = getOrCreateDependencyNode(value1);
        auto* node2 = getOrCreateDependencyNode(value2);
        if (node2->nodesThatDependOnMe.insert(node1).second) {
            node1->numberOfNodesThatIDependOn++;
            unvisitedIndependentSet.erase(value1);
        }
    }

    bool hasUnVisitedIndependentValues() {
        if (!unvisitedIndependentSet.empty()) {
            return true;
        }
        checkCycleState();
        return false;
    }

    T pop() {
        checkCycleState();
        if (unvisitedIndependentSet.empty()) {
            return T{};
        }
        T value = *unvisitedIndependentSet.begin();
        unvisitedIndependentSet.erase(unvisitedIndependentSet.begin());
        remove(value);
        return value;
    }

    bool hasCycles() {
        try {
            std::set<T> visited;
            while (!unvisitedIndependentSet.empty()) {
                auto values = getUnvisitedIndependentValues();
                visited.insert(values.begin(), values.end());
                for (const auto& k : values) {
                    auto it = nodeMap.find(k);
                    if (it == nodeMap.end()) continue;
                    auto* node = it->second.get();
                    for (auto* depNode : node->nodesThatDependOnMe) {
                        if (--depNode->numberOfNodesThatIDependOn == 0) {
                            unvisitedIndependentSet.insert(depNode->value);
                        }
                    }
                }
            }
            if (visited.size() != nodeMap.size()) {
                return true;
            }
        } catch (...) {
            reset();
            throw;
        }
        reset();
        return false;
    }

    std::set<T> getUnvisitedIndependentValues() {
        checkCycleState();
        visitedButNotDeletedCount += static_cast<int>(unvisitedIndependentSet.size());
        std::set<T> returnSet = std::move(unvisitedIndependentSet);
        unvisitedIndependentSet.clear();
        return returnSet;
    }

    std::set<T> getAllIndependentValues() const {
        std::set<T> result;
        for (const auto& kv : nodeMap) {
            if (kv.second->numberOfNodesThatIDependOn == 0) {
                result.insert(kv.second->value);
            }
        }
        return result;
    }

    void remove(const T& value) {
        auto it = nodeMap.find(value);
        if (it == nodeMap.end()) return;
        auto* node = it->second.get();

        if (!node->nodesThatDependOnMe.empty()) {
            for (auto* depNode : node->nodesThatDependOnMe) {
                if (--depNode->numberOfNodesThatIDependOn == 0) {
                    unvisitedIndependentSet.insert(depNode->value);
                }
            }
        }

        nodeMap.erase(it);
        if (unvisitedIndependentSet.erase(value)) {
            visitedButNotDeletedCount--;
        }
    }

    std::set<T> getDependentValues(const T& value) const {
        std::set<T> result;
        auto it = nodeMap.find(value);
        if (it != nodeMap.end()) {
            auto* node = it->second.get();
            for (auto* child : node->nodesThatDependOnMe) {
                result.insert(child->value);
            }
        }
        return result;
    }

    void debugPrint() const {
        std::cout << "Graph size=" << size() << " unvisited=" << unvisitedIndependentSet.size()
                  << " visitedNotDeleted=" << visitedButNotDeletedCount << std::endl;
        for (const auto& kv : nodeMap) {
            std::cout << "  Node: " << kv.second->value
                      << " depsOnMe=" << kv.second->nodesThatDependOnMe.size()
                      << " iDependOn=" << kv.second->numberOfNodesThatIDependOn << std::endl;
        }
    }
};

} // namespace ghidra
