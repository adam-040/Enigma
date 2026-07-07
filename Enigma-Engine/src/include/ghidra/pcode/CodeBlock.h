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

#include <ghidra/AddressSetView.h>
#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <string>
#include <vector>

namespace ghidra {
class TaskMonitor;
}

namespace ghidra::pcode {

class CodeBlockReferenceIterator;
class CodeBlockModel;

class CodeBlock : public AddressSetView {
public:
    virtual Address getFirstStartAddress() const = 0;
    virtual std::vector<Address> getStartAddresses() const = 0;
    virtual std::string getName() const = 0;
    virtual FlowType getFlowType() const = 0;
    virtual int getNumSources(TaskMonitor* monitor) = 0;
    virtual CodeBlockReferenceIterator* getSources(TaskMonitor* monitor) = 0;
    virtual int getNumDestinations(TaskMonitor* monitor) = 0;
    virtual CodeBlockReferenceIterator* getDestinations(TaskMonitor* monitor) = 0;
    virtual CodeBlockModel* getModel() const = 0;
};

} // namespace ghidra::pcode
