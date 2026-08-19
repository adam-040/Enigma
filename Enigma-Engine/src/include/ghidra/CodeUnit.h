/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file CodeUnit.h
/// \brief Base class for instructions and data in the program listing
/// Translated from: ghidra.program.model.listing.CodeUnit
#pragma once

#include <ghidra/Address.h>
#include <ghidra/RefType.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class DataType;
class Reference;
class Symbol;
class Program;

class CodeUnit {
public:
    static constexpr int FALLTHROUGH = -1;
    static constexpr int UNKNOWN_FLOW_TYPE = -2;

    CodeUnit() = default;
    CodeUnit(Program* program, Address address, DataType* dataType);

    virtual ~CodeUnit() = default;

    Program* getProgram() const { return program_; }
    Address getAddress() const { return address_; }
    void setAddress(Address addr) { address_ = addr; }

    DataType* getDataType() const { return dataType_; }
    void setDataType(DataType* type) { dataType_ = type; }

    virtual int getLength() const = 0;

    Address getMaxAddress() const;

    const std::string& getComment() const { return comment_; }
    void setComment(const std::string& c) { comment_ = c; }

    const std::string& getPlateComment() const { return plateComment_; }
    void setPlateComment(const std::string& c) { plateComment_ = c; }

    const std::string& getPreComment() const { return preComment_; }
    void setPreComment(const std::string& c) { preComment_ = c; }

    const std::string& getPostComment() const { return postComment_; }
    void setPostComment(const std::string& c) { postComment_ = c; }

    const std::string& getRepeatableComment() const { return repeatableComment_; }
    void setRepeatableComment(const std::string& c) { repeatableComment_ = c; }

    const std::vector<Reference*>& getReferencesFrom() const { return referencesFrom_; }
    void addReferenceFrom(Reference* ref) { referencesFrom_.push_back(ref); }

    const std::vector<Reference*>& getReferencesTo() const { return referencesTo_; }
    void addReferenceTo(Reference* ref) { referencesTo_.push_back(ref); }

    bool hasReferences() const;

    virtual std::string toString() const = 0;

protected:
    Program* program_ = nullptr;
    Address address_;
    DataType* dataType_ = nullptr;
    std::string comment_;
    std::string plateComment_;
    std::string preComment_;
    std::string postComment_;
    std::string repeatableComment_;
    std::vector<Reference*> referencesFrom_;
    std::vector<Reference*> referencesTo_;
};

} // namespace ghidra
