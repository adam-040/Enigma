/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 */
/// \file LongIterator.cpp
/// \brief Implementation of LongIterator EMPTY singleton

#include "ghidra/LongIterator.h"

namespace ghidra {

namespace {

class EmptyLongIterator : public LongIterator {
public:
    bool hasNext() override { return false; }
    int64_t next() override { return 0; }
    bool hasPrevious() override { return false; }
    int64_t previous() override { return 0; }
};

} // anonymous namespace

LongIterator& LongIterator::EMPTY() {
    static EmptyLongIterator instance;
    return instance;
}

} // namespace ghidra
