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

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <memory>
#include <string>
#include <vector>

namespace ghidra {

class CodeBlockModel;
class CodeBlockReferenceIterator;
class TaskMonitor;
class CancelledException;

/**
 * CodeBlock defines an interface for a block of code addresses.
 * Translated from: ghidra.program.model.block.CodeBlock
 */
class CodeBlock {
public:
    virtual ~CodeBlock() = default;

    virtual std::string getName() const = 0;

    virtual Address getMinAddress() const = 0;
    virtual Address getMaxAddress() const = 0;
    virtual AddressSetView* getAddressSet() const = 0;
    virtual Address getFirstStartAddress() const = 0;
    virtual Address* getStartAddresses() const = 0;

    virtual int getNumAddresses() const = 0;

    virtual bool contains(Address addr) const = 0;

    virtual CodeBlockModel* getModel() const = 0;

    virtual CodeBlockReferenceIterator* getSources(TaskMonitor& monitor) = 0;
    virtual CodeBlockReferenceIterator* getDestinations(TaskMonitor& monitor) = 0;

    virtual int getNumSources(TaskMonitor& monitor) = 0;
    virtual int getNumDestinations(TaskMonitor& monitor) = 0;

    virtual bool hasValidSymbol() const = 0;

    virtual bool isEmpty() const = 0;

    virtual int compareTo(const CodeBlock& other) const = 0;

    virtual size_t hash() const = 0;
};

} // namespace ghidra
