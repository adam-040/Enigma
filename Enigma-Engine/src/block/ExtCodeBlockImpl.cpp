/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include <ghidra/block/ExtCodeBlockImpl.h>
#include <ghidra/block/CodeBlockModel.h>
#include <ghidra/block/CodeBlockReferenceIterator.h>
#include <ghidra/block/CodeBlockReferenceImpl.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/CancelledException.h>

namespace ghidra {

namespace {
    class EmptyCodeBlockReferenceIterator : public CodeBlockReferenceIterator {
    public:
        CodeBlockReference* next() override { return nullptr; }
        bool hasNext() const override { return false; }
    };
}

ExtCodeBlockImpl::ExtCodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name)
    : CodeBlockImpl(model, program, name) {
}

bool ExtCodeBlockImpl::hasValidSymbol() const {
    return true;
}

CodeBlockReferenceIterator* ExtCodeBlockImpl::getSources(TaskMonitor& monitor) {
    return new EmptyCodeBlockReferenceIterator();
}

CodeBlockReferenceIterator* ExtCodeBlockImpl::getDestinations(TaskMonitor& monitor) {
    return new EmptyCodeBlockReferenceIterator();
}

int ExtCodeBlockImpl::getNumSources(TaskMonitor& monitor) {
    return 0;
}

int ExtCodeBlockImpl::getNumDestinations(TaskMonitor& monitor) {
    return 0;
}

} // namespace ghidra
