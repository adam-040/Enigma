/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ListLinked.h
/// \brief A doubly-linked list with a non-failing iterator.
#pragma once

#include <vector>
#include <stdexcept>

namespace ghidra {

template<typename T>
class ListLinked {
private:
    struct Node {
        T data;
        Node* prev;
        Node* next;
        Node(Node* p, Node* n, const T& d) : data(d), prev(p), next(n) {}
    };

    Node* terminal_;

public:
    class iterator {
    public:
        Node* cur_;

        explicit iterator(Node* c = nullptr) : cur_(c) {}

        bool hasNext() const { return cur_->next->data != nullptr; }
        bool hasPrevious() const { return cur_->data != nullptr; }

        T next() {
            cur_ = cur_->next;
            if (cur_->data == nullptr) throw std::out_of_range("no next");
            return cur_->data;
        }

        T previous() {
            cur_ = cur_->prev;
            if (cur_->data == nullptr) throw std::out_of_range("no previous");
            return cur_->data;
        }

        void remove() {
            if (cur_->data == nullptr) return;
            cur_->next->prev = cur_->prev;
            cur_->prev->next = cur_->next;
            cur_ = cur_->prev;
        }

        T operator*() const { return cur_->data; }
        T* operator->() const { return &cur_->data; }

        bool operator==(const iterator& o) const { return cur_ == o.cur_; }
        bool operator!=(const iterator& o) const { return cur_ != o.cur_; }
    };

    ListLinked() {
        terminal_ = new Node(nullptr, nullptr, T());
        terminal_->prev = terminal_;
        terminal_->next = terminal_;
    }

    ~ListLinked() {
        clear();
        delete terminal_;
    }

    ListLinked(const ListLinked&) = delete;
    ListLinked& operator=(const ListLinked&) = delete;

    iterator add(const T& o) {
        Node* n = new Node(terminal_->prev, terminal_, o);
        terminal_->prev->next = n;
        terminal_->prev = n;
        return iterator(n);
    }

    iterator insertAfter(iterator itr, const T& o) {
        Node* cur = itr.cur_;
        Node* n = new Node(cur, cur->next, o);
        cur->next->prev = n;
        cur->next = n;
        return iterator(n);
    }

    iterator insertBefore(iterator itr, const T& o) {
        Node* cur = itr.cur_;
        Node* n = new Node(cur->prev, cur, o);
        cur->prev->next = n;
        cur->prev = n;
        return iterator(n);
    }

    void remove(iterator itr) {
        Node* cur = itr.cur_;
        if (cur->data == nullptr) return;
        cur->prev->next = cur->next;
        cur->next->prev = cur->prev;
        delete cur;
    }

    iterator begin() const { return iterator(terminal_->next); }
    iterator end() const { return iterator(const_cast<Node*>(terminal_)); }
    iterator iterator_() const { return iterator(terminal_); }

    void clear() {
        Node* cur = terminal_->next;
        while (cur != terminal_) {
            Node* next = cur->next;
            delete cur;
            cur = next;
        }
        terminal_->next = terminal_;
        terminal_->prev = terminal_;
    }

    bool empty() const { return terminal_->next == terminal_; }

    T first() const { return terminal_->next->data; }
    T last() const { return terminal_->prev->data; }

    int size() const {
        int n = 0;
        for (Node* c = terminal_->next; c != terminal_; c = c->next) ++n;
        return n;
    }
};

} // namespace ghidra
