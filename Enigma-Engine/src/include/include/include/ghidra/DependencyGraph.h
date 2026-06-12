/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file DependencyGraph.h
/// \brief Standard DependencyGraph using hash-based containers
/// Translated from: ghidra.util.graph.DependencyGraph
#pragma once

#include "ghidra/AbstractDependencyGraph.h"
#include <unordered_map>
#include <set>
#include <memory>

namespace ghidra {

template<typename T>
class DependencyGraph : public AbstractDependencyGraph<T> {
public:
    DependencyGraph() : AbstractDependencyGraph<T>() {}

    DependencyGraph(const DependencyGraph<T>& other) {
        for (const auto& kv : other.nodeMap) {
            this->addValue(kv.first);
            auto* node = kv.second.get();
            if (!node->nodesThatDependOnMe.empty()) {
                for (auto* child : node->nodesThatDependOnMe) {
                    this->addDependency(child->value, kv.first);
                }
            }
        }
    }

    DependencyGraph<T>* copy() const override {
        return new DependencyGraph<T>(*this);
    }

protected:
    std::unique_ptr<std::unordered_map<T, std::unique_ptr<typename AbstractDependencyGraph<T>::DependencyNode>>> createNodeMap() override {
        return std::make_unique<std::unordered_map<T, std::unique_ptr<typename AbstractDependencyGraph<T>::DependencyNode>>>();
    }

    std::unique_ptr<std::set<T>> createNodeSet() override {
        return std::make_unique<std::set<T>>();
    }

    std::unique_ptr<std::set<typename AbstractDependencyGraph<T>::DependencyNode*>> createDependencyNodeSet() override {
        return std::make_unique<std::set<typename AbstractDependencyGraph<T>::DependencyNode*>>();
    }

public:
    std::set<T> getNodeMapValues() override {
        std::set<T> result;
        for (const auto& kv : this->nodeMap) {
            result.insert(kv.first);
        }
        return result;
    }
};

} // namespace ghidra
