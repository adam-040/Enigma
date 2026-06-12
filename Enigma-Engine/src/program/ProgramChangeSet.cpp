/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
/// \file ProgramChangeSet.cpp
/// \brief Tracks changes made to a program for undo/redo
/// Translated from: ghidra.program.database.ProgramChangeSet

#include <ghidra/ProgramChangeSet.h>

namespace ghidra {

void ProgramChangeSet::addChange(int subKey, int index, int oldVal, int newVal,
                                  const Address& addr, const std::string& desc) {
    currentChanges_.emplace_back(subKey, index, oldVal, newVal, addr, desc);
}

void ProgramChangeSet::startUndoGroup() {
    undoGroups_.push_back(currentChanges_);
    currentChanges_.clear();
}

void ProgramChangeSet::endUndoGroup() {
    if (!currentChanges_.empty()) {
        undoGroups_.push_back(currentChanges_);
        currentChanges_.clear();
    }
}

std::vector<ProgramChangeRecord> ProgramChangeSet::undo() {
    if (undoGroups_.empty()) return {};
    redoGroups_.push_back(undoGroups_.back());
    auto changes = undoGroups_.back();
    undoGroups_.pop_back();
    return changes;
}

std::vector<ProgramChangeRecord> ProgramChangeSet::redo() {
    if (redoGroups_.empty()) return {};
    undoGroups_.push_back(redoGroups_.back());
    auto changes = redoGroups_.back();
    redoGroups_.pop_back();
    return changes;
}

void ProgramChangeSet::clearUndos() {
    undoGroups_.clear();
    redoGroups_.clear();
    currentChanges_.clear();
}

void ProgramChangeSet::addChangedAddress(const Address& addr) {
    changedAddresses_.add(addr);
}

} // namespace ghidra
