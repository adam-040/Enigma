#pragma once

#include <string>
#include <memory>
#include <optional>

namespace ghidra {

template <typename K, typename V>
class RedBlackEntry {
public:
    enum class NodeColor {
        RED, BLACK
    };

    K key;
    V value;
    std::optional<NodeColor> color;
    RedBlackEntry* parent = nullptr;
    RedBlackEntry* left = nullptr;
    RedBlackEntry* right = nullptr;

    RedBlackEntry(K key, V value, RedBlackEntry* parent)
        : key(key), value(value), color(NodeColor::BLACK), parent(parent) {}

    V getValue() const {
        return value;
    }

    void setValue(V newValue) {
        value = newValue;
    }

    K getKey() const {
        return key;
    }

    RedBlackEntry* getSuccessor() const {
        if (right) {
            RedBlackEntry* node = right;
            while (node->left) {
                node = node->left;
            }
            return node;
        }
        RedBlackEntry* node = const_cast<RedBlackEntry*>(this);
        while (node->parent) {
            if (node->isLeftChild()) {
                return node->parent;
            }
            node = node->parent;
        }
        return nullptr;
    }

    RedBlackEntry* getPredecessor() const {
        if (left) {
            RedBlackEntry* node = left;
            while (node->right) {
                node = node->right;
            }
            return node;
        }
        RedBlackEntry* node = const_cast<RedBlackEntry*>(this);
        while (node->parent) {
            if (!node->isLeftChild()) {
                return node->parent;
            }
            node = node->parent;
        }
        return nullptr;
    }

    bool isLeftChild() const {
        return parent && parent->left == this;
    }

    bool isRightChild() const {
        return parent && parent->right == this;
    }

    bool isDisposed() const {
        return !color.has_value();
    }
};

} // namespace ghidra
