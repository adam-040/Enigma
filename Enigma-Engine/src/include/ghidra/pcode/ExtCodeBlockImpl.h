/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#pragma once

#include <ghidra/AddressSet.h>
#include <ghidra/pcode/CodeBlock.h>
#include <ghidra/pcode/CodeBlockReferenceIterator.h>

namespace ghidra::pcode {

class CodeBlockModel;

class ExtCodeBlockImpl : public AddressSet, public CodeBlock {
public:
    ExtCodeBlockImpl(CodeBlockModel* model, const Address& extAddr);

    Address getFirstStartAddress() const override { return extAddr_; }
    std::vector<Address> getStartAddresses() const override { return {extAddr_}; }
    FlowType getFlowType() const override { return RefTypes::INVALID; }
    CodeBlockModel* getModel() const override { return model_; }
    std::string getName() const override;

    int getNumDestinations(TaskMonitor* monitor) override { return 0; }
    CodeBlockReferenceIterator* getDestinations(TaskMonitor* monitor) override;
    int getNumSources(TaskMonitor* monitor) override;
    CodeBlockReferenceIterator* getSources(TaskMonitor* monitor) override;

    std::size_t hash() const { return extAddr_.hash(); }

private:
    CodeBlockModel* model_;
    Address extAddr_;
};

class EmptyCodeBlockReferenceIterator : public CodeBlockReferenceIterator {
public:
    bool hasNext() override { return false; }
    CodeBlockReference* next() override { return nullptr; }
};

} // namespace ghidra::pcode
