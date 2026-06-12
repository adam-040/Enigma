/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/HashedFunctionAddressCorrelation.h"
#include "ghidra/correlate/HashStore.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/HashCalculator.h"
#include "ghidra/correlate/MnemonicHashCalculator.h"
#include "ghidra/correlate/DisambiguateStrategy.h"
#include "ghidra/correlate/DisambiguateByParent.h"
#include "ghidra/correlate/DisambiguateByChild.h"
#include "ghidra/correlate/DisambiguateByBytes.h"
#include "ghidra/correlate/DisambiguateByParentWithOrder.h"
#include "ghidra/Function.h"
#include "ghidra/Program.h"
#include "ghidra/AddressSetView.h"
#include "ghidra/Instruction.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/CancelledException.h"
#include "ghidra/MemoryAccessException.h"
#include <algorithm>

namespace ghidra {

HashedFunctionAddressCorrelation::HashedFunctionAddressCorrelation(
    Function* leftFunction, Function* rightFunction, TaskMonitor* monitor) {
    if (leftFunction == nullptr || rightFunction == nullptr) {
        throw std::invalid_argument("Functions can't be null!");
    }
    functions_ = Duo<Function*>(leftFunction, rightFunction);
    monitor_ = monitor;
    srcStore_ = new HashStore(leftFunction, monitor);
    destStore_ = new HashStore(rightFunction, monitor);
    hashCalc_ = new MnemonicHashCalculator();
    calculate();
    buildFinalMaps();
}

HashedFunctionAddressCorrelation::~HashedFunctionAddressCorrelation() {
    delete srcStore_;
    delete destStore_;
    delete hashCalc_;
}

Program* HashedFunctionAddressCorrelation::getProgram(Side side) {
    return functions_.get(side)->getProgram();
}

AddressSetView* HashedFunctionAddressCorrelation::getAddresses(Side side) {
    return const_cast<AddressSet*>(&functions_.get(side)->getBody());
}

Address HashedFunctionAddressCorrelation::getAddress(Side side, Address otherSideAddress) {
    if (side == Side::LEFT) {
        auto it = destToSrc_.find(otherSideAddress);
        if (it != destToSrc_.end()) return it->second;
        return Address();
    }
    auto it = srcToDest_.find(otherSideAddress);
    if (it != srcToDest_.end()) return it->second;
    return Address();
}

Function* HashedFunctionAddressCorrelation::getFunction(Side side) {
    return functions_.get(side);
}

int HashedFunctionAddressCorrelation::getTotalInstructionsInFirst() const {
    return srcStore_->getTotalInstructions();
}

int HashedFunctionAddressCorrelation::getTotalInstructionsInSecond() const {
    return destStore_->getTotalInstructions();
}

int HashedFunctionAddressCorrelation::numMatchedInstructionsInFirst() const {
    return srcStore_->numMatchedInstructions();
}

int HashedFunctionAddressCorrelation::numMatchedInstructionsInSecond() const {
    return destStore_->numMatchedInstructions();
}

std::list<Instruction*> HashedFunctionAddressCorrelation::getUnmatchedInstructionsInFirst() {
    return srcStore_->getUnmatchedInstructions();
}

std::list<Instruction*> HashedFunctionAddressCorrelation::getUnmatchedInstructionsInSecond() {
    return destStore_->getUnmatchedInstructions();
}

void HashedFunctionAddressCorrelation::declareMatch(HashEntry* srcEntry, InstructHash* srcInstruct,
                                                     HashEntry* destEntry, InstructHash* destInstruct) {
    bool cancelMatch = false;
    int matchSize = srcEntry->hash.size;

    if (!srcInstruct->allUnknown(matchSize)) {
        srcStore_->removeHash(srcEntry);
        cancelMatch = true;
    }
    if (!destInstruct->allUnknown(matchSize)) {
        destStore_->removeHash(destEntry);
        cancelMatch = true;
    }
    if (cancelMatch) {
        return;
    }

    std::vector<Instruction*> srcInstructVec;
    std::vector<Instruction*> destInstructVec;
    std::vector<CodeBlock*> srcBlockVec;
    std::vector<CodeBlock*> destBlockVec;

    HashStore::NgramMatch srcMatch;
    HashStore::NgramMatch destMatch;
    HashStore::extendMatch(matchSize, srcInstruct, &srcMatch, destInstruct, &destMatch, hashCalc_);
    srcStore_->matchHash(&srcMatch, srcInstructVec, srcBlockVec);
    destStore_->matchHash(&destMatch, destInstructVec, destBlockVec);

    for (size_t i = 0; i < srcInstructVec.size(); ++i) {
        srcToDest_[srcInstructVec[i]->getAddress()] = destInstructVec[i]->getAddress();
    }
}

std::map<Hash, HashedFunctionAddressCorrelation::DisambiguatorEntry>
HashedFunctionAddressCorrelation::constructDisambiguatorTree(
    HashEntry* entry, HashStore* store, DisambiguateStrategy* strategy) {
    std::map<Hash, DisambiguatorEntry> entryMap;
    int matchSize = entry->hash.size;
    for (InstructHash* curInstruct : entry->instList) {
        std::vector<Hash> hashList = strategy->calcHashes(curInstruct, matchSize, store);
        for (const Hash& curHash : hashList) {
            auto it = entryMap.find(curHash);
            if (it == entryMap.end()) {
                entryMap.insert(std::make_pair(curHash, DisambiguatorEntry(curHash, curInstruct)));
            }
            else {
                it->second.count += 1;
            }
        }
    }
    return entryMap;
}

int HashedFunctionAddressCorrelation::disambiguateNgramsWithStrategy(
    DisambiguateStrategy* strategy, HashEntry* srcEntry, HashEntry* destEntry) {
    std::map<Hash, DisambiguatorEntry> srcDisambig =
        constructDisambiguatorTree(srcEntry, srcStore_, strategy);
    std::map<Hash, DisambiguatorEntry> destDisambig =
        constructDisambiguatorTree(destEntry, destStore_, strategy);

    int count = 0;
    for (auto& srcPair : srcDisambig) {
        DisambiguatorEntry& srcDisEntry = srcPair.second;
        if (srcDisEntry.count != 1) continue;
        if (srcDisEntry.instruct->isMatched) continue;

        auto destIt = destDisambig.find(srcPair.first);
        if (destIt == destDisambig.end()) continue;
        DisambiguatorEntry& destDisEntry = destIt->second;
        if (destDisEntry.count != 1) continue;
        if (destDisEntry.instruct->isMatched) continue;

        declareMatch(srcEntry, srcDisEntry.instruct, destEntry, destDisEntry.instruct);
        count += 1;
    }
    return count;
}

bool HashedFunctionAddressCorrelation::disambiguateMatchingNgrams(HashEntry* srcEntry, HashEntry* destEntry) {
    if (srcEntry->hasDuplicateBlocks()) return false;
    if (destEntry->hasDuplicateBlocks()) return false;
    if (srcEntry->hash.size != destEntry->hash.size) return false;

    {
        DisambiguateByParent strategy;
        int count = disambiguateNgramsWithStrategy(&strategy, srcEntry, destEntry);
        if (count != 0) return true;
    }
    {
        DisambiguateByChild strategy;
        int count = disambiguateNgramsWithStrategy(&strategy, srcEntry, destEntry);
        if (count != 0) return true;
    }
    {
        DisambiguateByBytes strategy;
        int count = disambiguateNgramsWithStrategy(&strategy, srcEntry, destEntry);
        if (count != 0) return true;
    }
    {
        DisambiguateByParentWithOrder strategy;
        int count = disambiguateNgramsWithStrategy(&strategy, srcEntry, destEntry);
        if (count != 0) return true;
    }
    return false;
}

void HashedFunctionAddressCorrelation::findMatches() {
    while (!srcStore_->isEmpty() && !destStore_->isEmpty()) {
        HashEntry* srcEntry = srcStore_->getFirstEntry();
        if (srcEntry == nullptr) break;
        HashEntry* destEntry = destStore_->getEntry(srcEntry->hash);
        if (destEntry == nullptr) {
            srcStore_->removeHash(srcEntry);
        }
        else if (srcEntry->instList.size() == 1 && destEntry->instList.size() == 1) {
            declareMatch(srcEntry, srcEntry->instList.front(), destEntry, destEntry->instList.front());
        }
        else {
            HashEntry* destEntry2 = destStore_->getFirstEntry();
            if (destEntry2 == nullptr) break;
            HashEntry* srcEntry2 = srcStore_->getEntry(destEntry2->hash);
            if (srcEntry2 == nullptr) {
                destStore_->removeHash(destEntry2);
            }
            else if (srcEntry2->instList.size() == 1 && destEntry2->instList.size() == 1) {
                declareMatch(srcEntry2, srcEntry2->instList.front(), destEntry2, destEntry2->instList.front());
            }
            else {
                if (!disambiguateMatchingNgrams(srcEntry, destEntry)) {
                    srcStore_->removeHash(srcEntry);
                }
            }
        }
    }
}

void HashedFunctionAddressCorrelation::runPasses(int minLength, int maxLength, bool wholeBlock, bool matchBlock, int maxPasses) {
    srcStore_->calcHashes(minLength, maxLength, wholeBlock, matchBlock, hashCalc_);
    destStore_->calcHashes(minLength, maxLength, wholeBlock, matchBlock, hashCalc_);
    for (int pass = 0; pass < maxPasses; ++pass) {
        int curMatch = srcStore_->numMatchedInstructions();
        if (curMatch == srcStore_->getTotalInstructions()) break;

        srcStore_->clearSort();
        destStore_->clearSort();

        srcStore_->insertHashes();
        destStore_->insertHashes();

        findMatches();
        if (curMatch == srcStore_->numMatchedInstructions()) break;
    }
}

void HashedFunctionAddressCorrelation::calculate() {
    srcStore_->calcHashes(5, 10, false, false, hashCalc_);
    srcStore_->insertHashes();
    destStore_->calcHashes(5, 10, false, false, hashCalc_);
    destStore_->insertHashes();

    findMatches();

    if (srcStore_->numMatchedInstructions() == srcStore_->getTotalInstructions()) return;
    if (destStore_->numMatchedInstructions() == destStore_->getTotalInstructions()) return;

    runPasses(3, 4, true, true, 10);

    if (srcStore_->numMatchedInstructions() == srcStore_->getTotalInstructions()) return;
    if (destStore_->numMatchedInstructions() == destStore_->getTotalInstructions()) return;

    int curMatch = srcStore_->numMatchedInstructions();
    runPasses(5, 10, false, false, 3);

    if (srcStore_->numMatchedInstructions() == curMatch) return;
    if (srcStore_->numMatchedInstructions() == srcStore_->getTotalInstructions()) return;
    if (destStore_->numMatchedInstructions() == destStore_->getTotalInstructions()) return;

    runPasses(3, 4, true, true, 10);
}

void HashedFunctionAddressCorrelation::buildFinalMaps() {
    for (auto& entry : srcToDest_) {
        destToSrc_[entry.second] = entry.first;
    }
}

} // namespace ghidra
