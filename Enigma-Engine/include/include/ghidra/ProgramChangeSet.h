/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramChangeSet.h
/// \brief Tracks changes made to a program for undo/redo
/// Translated from: ghidra.program.database.ProgramChangeSet
#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/NormalizedAddressSet.h>
#include <vector>
#include <string>
#include <memory>

namespace ghidra {

class AddressMap;
class ProgramChangeRecord {
public:
    ProgramChangeRecord() = default;
    ProgramChangeRecord(int subKey, int index, int oldVal, int newVal,
                        const Address& addr, const std::string& desc)
        : subKey_(subKey), index_(index), oldValue_(oldVal), newValue_(newVal),
          address_(addr), description_(desc) {}

    int getSubKey() const { return subKey_; }
    int getIndex() const { return index_; }
    int getOldValue() const { return oldValue_; }
    int getNewValue() const { return newValue_; }
    Address getAddress() const { return address_; }
    const std::string& getDescription() const { return description_; }

private:
    int subKey_ = 0;
    int index_ = 0;
    int oldValue_ = 0;
    int newValue_ = 0;
    Address address_;
    std::string description_;
};

class ProgramChangeSet {
public:
    ProgramChangeSet() = default;
    ProgramChangeSet(AddressMap* addrMap, int maxUndos)
        : addrMap_(addrMap), maxUndos_(maxUndos), changedAddresses_(addrMap) {}

    void addChange(int subKey, int index, int oldVal, int newVal,
                   const Address& addr, const std::string& desc);

    void startUndoGroup();
    void endUndoGroup();

    bool canUndo() const { return !undoGroups_.empty(); }
    bool canRedo() const { return !redoGroups_.empty(); }

    std::vector<ProgramChangeRecord> undo();

    std::vector<ProgramChangeRecord> redo();

    void clearUndos();

    int getUndoCount() const { return static_cast<int>(undoGroups_.size()); }
    int getRedoCount() const { return static_cast<int>(redoGroups_.size()); }

    const NormalizedAddressSet& getChangedAddresses() const { return changedAddresses_; }
    void addChangedAddress(const Address& addr);

private:
    AddressMap* addrMap_ = nullptr;
    int maxUndos_ = 100;
    std::vector<std::vector<ProgramChangeRecord>> undoGroups_;
    std::vector<std::vector<ProgramChangeRecord>> redoGroups_;
    std::vector<ProgramChangeRecord> currentChanges_;
    NormalizedAddressSet changedAddresses_;
};

} // namespace ghidra
