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

#include <ghidra/block/CodeBlock.h>
#include <ghidra/AddressSet.h>
#include <string>
#include <vector>

namespace ghidra {

class CodeBlockModel;
class RefType;
class Program;

/**
 * CodeBlockImpl is the implementation of the CodeBlock interface.
 * Translated from: ghidra.program.model.block.CodeBlockImpl
 */
class CodeBlockImpl : public CodeBlock {
private:
    std::string name_;
    CodeBlockModel* model_;
    Program* program_;
    AddressSet addressSet_;
    std::vector<Address> startAddresses_;

public:
    CodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name);
    CodeBlockImpl(CodeBlockModel* model, Program* program, const std::string& name,
                  const AddressSetView& addrSet);

    ~CodeBlockImpl() override = default;

    std::string getName() const override { return name_; }
    void setName(const std::string& name) { name_ = name; }

    Address getMinAddress() const override;
    Address getMaxAddress() const override;
    AddressSetView* getAddressSet() const override { return const_cast<AddressSet*>(&addressSet_); }
    Address getFirstStartAddress() const override;
    Address* getStartAddresses() const override;

    int getNumAddresses() const override { return static_cast<int>(addressSet_.getNumAddresses()); }

    bool contains(Address addr) const override;

    CodeBlockModel* getModel() const override { return model_; }
    void setModel(CodeBlockModel* model) { model_ = model; }

    CodeBlockReferenceIterator* getSources(TaskMonitor& monitor) override;
    CodeBlockReferenceIterator* getDestinations(TaskMonitor& monitor) override;

    int getNumSources(TaskMonitor& monitor) override;
    int getNumDestinations(TaskMonitor& monitor) override;

    bool hasValidSymbol() const override;

    bool isEmpty() const override { return addressSet_.isEmpty(); }

    int compareTo(const CodeBlock& other) const override;
    size_t hash() const override;

    void addStartAddress(const Address& addr);
    void setAddressSet(const AddressSetView& addrSet);
    void addRange(const Address& start, const Address& end);
};

} // namespace ghidra
