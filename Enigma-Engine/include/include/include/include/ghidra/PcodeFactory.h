/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file PcodeFactory.h
/// \brief Interface for classes that build PcodeOps and Varnodes.
/// Translated from: ghidra.program.model.pcode.PcodeFactory
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/SequenceNumber.h>
#include <ghidra/Varnode.h>
#include <ghidra/PcodeOp.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class PcodeDataTypeManager;
class VariableStorage;
class DataType;
class HighSymbol;

/// Interface for classes that build PcodeOps and Varnodes.
/// Implemented in Java by PcodeSyntaxTree and the various Architecture
/// classes; the C++ port only supports PcodeSyntaxTree for now.
class PcodeFactory {
public:
    virtual ~PcodeFactory() = default;

    /// @return the AddressFactory used by this factory
    virtual AddressFactory* getAddressFactory() = 0;

    /// @return the PcodeDataTypeManager used to convert strings to data types
    virtual PcodeDataTypeManager* getDataTypeManager() = 0;

    /// Create a new Varnode with the given size and location
    virtual Varnode* newVarnode(int sz, const Address& addr) = 0;

    /// Create a new Varnode with the given size, location, and reference id
    /// The id allows the Varnode to be retrieved later via getRef()
    virtual Varnode* newVarnode(int sz, const Address& addr, int refId) = 0;

    /// Create a VariableStorage representing a value split across multiple
    /// physical locations. The pieces are passed in as a vector of Varnodes
    /// and the storage is also assigned a join-space Address.
    virtual VariableStorage* getJoinStorage(const std::vector<Varnode*>& pieces) = 0;

    /// Get the join-space Address corresponding to a multi-piece storage.
    /// The storage must have been previously registered by getJoinStorage().
    /// Returns nullptr if the storage is not multi-piece or was not registered.
    virtual Address getJoinAddress(VariableStorage* storage) = 0;

    /// Build a storage object for a particular Varnode.
    /// Returns a heap-allocated VariableStorage the caller owns.
    virtual VariableStorage* buildStorage(Varnode* vn) = 0;

    /// Return a Varnode given its reference id, or nullptr if not registered.
    virtual Varnode* getRef(int refid) = 0;

    /// Get a PcodeOp given a reference id (corresponds to SequenceNumber.getTime()).
    virtual PcodeOp* getOpRef(int refid) = 0;

    /// Get the high symbol matching the given id that has been registered.
    virtual HighSymbol* getSymbol(int64_t symbolId) = 0;

    /// Mark (or unmark) the given Varnode as an input.
    /// Returns the altered Varnode (may differ from the input).
    virtual Varnode* setInput(Varnode* vn, bool val) = 0;

    /// Mark (or unmark) the given Varnode as address-tied.
    virtual void setAddrTied(Varnode* vn, bool val) = 0;

    /// Mark (or unmark) the given Varnode as persistent.
    virtual void setPersistent(Varnode* vn, bool val) = 0;

    /// Mark (or unmark) the given Varnode as unaffected.
    virtual void setUnaffected(Varnode* vn, bool val) = 0;

    /// Mark (or unmark) the given Varnode as volatile.
    virtual void setVolatile(Varnode* vn, bool val) = 0;

    /// Associate a specific merge group with the given Varnode.
    virtual void setMergeGroup(Varnode* vn, int16_t val) = 0;

    /// Attach a data-type to the given Varnode.
    virtual void setDataType(Varnode* vn, DataType* type) = 0;

    /// Create a new PcodeOp with the given opcode, sequence number,
    /// input Varnodes, and optional output Varnode.
    virtual PcodeOp* newOp(const SequenceNumber& sq, int opc,
                           const std::vector<Varnode*>& inputs, Varnode* output) = 0;
};

} // namespace ghidra
