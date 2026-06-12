/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file SymbolIterator.h
/// \brief Iterator interface for Symbol objects
#pragma once

#include <memory>

namespace ghidra {

class Symbol;

class SymbolIterator {
public:
    static SymbolIterator EMPTY_ITERATOR;

    SymbolIterator() = default;
    virtual ~SymbolIterator() = default;

    virtual bool hasNext() = 0;
    virtual std::shared_ptr<Symbol> next() = 0;
};

inline SymbolIterator SymbolIterator::EMPTY_ITERATOR = []() {
    class EmptySymbolIterator : public SymbolIterator {
    public:
        bool hasNext() override { return false; }
        std::shared_ptr<Symbol> next() override { return nullptr; }
    };
    return EmptySymbolIterator();
}();

} // namespace ghidra
