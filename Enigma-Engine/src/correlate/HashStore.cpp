/* ###
 * IP: GHIDRA (translated to C++ for Enigma Engine)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
#include "ghidra/correlate/HashStore.h"
#include "ghidra/correlate/Block.h"
#include "ghidra/correlate/InstructHash.h"
#include "ghidra/correlate/HashCalculator.h"
#include "ghidra/Function.h"
#include "ghidra/Program.h"
#include "ghidra/Listing.h"
#include "ghidra/Instruction.h"
#include "ghidra/AddressRange.h"
#include "ghidra/AddressSetView.h"
#include "ghidra/TaskMonitor.h"
#include "ghidra/CancelledException.h"
#include "ghidra/MemoryAccessException.h"
#include "ghidra/block/CodeBlock.h"
#include "ghidra/block/CodeBlockIterator.h"
#include "ghidra/block/BasicBlockModel.h"

namespace ghidra {

bool HashStore::HashOrderComparator::operator()(const HashEntry* o1, const HashEntry* o2) const {
    int sz1 = static_cast<int>(o1->instList.size());
    int sz2 = static_cast<int>(o2->instList.size());
    if (sz1 != sz2) return sz1 < sz2;
    if (o1->hash.size != o2->hash.size)
        return o1->hash.size > o2->hash.size;
    return static_cast<long long>(o1->hash.value) < static_cast<long long>(o2->hash.value);
}

HashStore::HashStore(Function* a, TaskMonitor* mon) {
    function_ = a;
    program_ = a->getProgram();
    monitor_ = mon;
    matchedBlockCount_ = 0;
    matchedInstructionCount_ = 0;
    totalInstructions_ = 0;
    initializeStructures();
}

void HashStore::initializeStructures() {
    BasicBlockModel blockModel(program_);
    CodeBlockIterator iter = blockModel.getCodeBlocksContaining(function_->getBody(), *monitor_);
    while (iter.hasNext()) {
        CodeBlock* block = iter.next();
        createBlock(block);
    }
}

void HashStore::createBlock(CodeBlock* codeBlock) {
    Block* res = new Block(codeBlock);
    std::vector<InstructHash*> instList;
    Listing* listing = program_->getListing();
    AddressRangeIterator* rangeIter = codeBlock->getAddressSet()->getAddressRanges(true);
    int index = 0;
    while (rangeIter->hasNext()) {
        const AddressRange& range = rangeIter->next();
        Address cur = range.getMinAddress();
        Address max = range.getMaxAddress();
        while (cur <= max) {
            Instruction* instruct = listing->getInstructionAt(cur);
            if (instruct != nullptr) {
                InstructHash* instHash = new InstructHash(instruct, res, index);
                instList.push_back(instHash);
                index += 1;
                totalInstructions_ += 1;
                cur = cur.add(instruct->getLength());
            }
            else {
                cur = cur.next();
            }
        }
    }
    delete rangeIter;
    res->instList.resize(instList.size());
    for (size_t i = 0; i < instList.size(); ++i) {
        res->instList[i] = instList[i];
    }
    blockList_[codeBlock->getFirstStartAddress()] = res;
}

void HashStore::insertNGram(const Hash& curHash, InstructHash* instHash) {
    auto it = hashSort_.find(curHash);
    HashEntry* entry = nullptr;
    if (it == hashSort_.end()) {
        entry = new HashEntry(curHash);
        hashSort_[curHash] = entry;
    }
    else {
        entry = it->second;
        matchSort_.erase(entry);
    }
    entry->instList.push_back(instHash);
    instHash->hashEntries[curHash] = entry;
    matchSort_.insert(entry);
}

void HashStore::insertInstructionNGrams(InstructHash* instHash) {
    for (size_t i = 0; i < instHash->nGrams.size(); ++i) {
        Hash& curHash = instHash->nGrams[i];
        if (curHash.size == 0) break;
        insertNGram(curHash, instHash);
    }
}

void HashStore::removeNGram(InstructHash* instHash, const Hash& curHash) {
    auto hit = instHash->hashEntries.find(curHash);
    if (hit == instHash->hashEntries.end()) return;
    HashEntry* hashEntry = hit->second;
    matchSort_.erase(hashEntry);
    hashEntry->instList.remove(instHash);
    if (hashEntry->instList.empty()) {
        hashSort_.erase(curHash);
    }
    else {
        matchSort_.insert(hashEntry);
    }
}

void HashStore::removeInstructionNGrams(InstructHash* instHash) {
    for (size_t i = 0; i < instHash->nGrams.size(); ++i) {
        Hash& curHash = instHash->nGrams[i];
        if (curHash.size == 0) continue;
        auto hit = instHash->hashEntries.find(curHash);
        if (hit == instHash->hashEntries.end()) continue;
        HashEntry* hashEntry = hit->second;
        matchSort_.erase(hashEntry);
        hashEntry->instList.remove(instHash);
        if (hashEntry->instList.empty()) {
            hashSort_.erase(curHash);
        }
        else {
            matchSort_.insert(hashEntry);
        }
    }
}

void HashStore::removeHash(HashEntry* hashEntry) {
    matchSort_.erase(hashEntry);
    hashSort_.erase(hashEntry->hash);
    for (InstructHash* instruct : hashEntry->instList) {
        instruct->hashEntries.erase(hashEntry->hash);
    }
}

void HashStore::calcHashes(int minLength, int maxLength, bool wholeBlock, bool matchOnly, HashCalculator* hashCalc) {
    for (auto& pair : blockList_) {
        pair.second->calcHashes(minLength, maxLength, wholeBlock, matchOnly, hashCalc);
    }
}

void HashStore::insertHashes() {
    for (auto& pair : blockList_) {
        Block* block = pair.second;
        for (size_t j = 0; j < block->instList.size(); ++j) {
            InstructHash* instruct = block->instList[j];
            if (instruct->isMatched) continue;
            insertInstructionNGrams(instruct);
        }
    }
}

void HashStore::matchHash(NgramMatch* match, std::vector<Instruction*>& instResult, std::vector<CodeBlock*>& blockResult) {
    Block* block = match->block;
    for (int index = match->startindex; index <= match->endindex; ++index) {
        InstructHash* curInstruct = block->instList[index];
        instResult.push_back(curInstruct->instruction);
        matchedInstructionCount_ += 1;
        curInstruct->isMatched = true;
        removeInstructionNGrams(curInstruct);
        curInstruct->nGrams.clear();
    }
    if (block->isMatched) return;
    matchedBlockCount_ += 1;
    block->setMatched(matchedBlockCount_);
    blockResult.push_back(block->origBlock);
    for (size_t i = 0; i < block->instList.size(); ++i) {
        InstructHash* curInstruct = block->instList[i];
        if (curInstruct->isMatched) continue;
        for (size_t j = 0; j < curInstruct->nGrams.size(); ++j) {
            Hash& curHash = curInstruct->nGrams[j];
            if (curHash.size == 0) continue;
            auto hit = curInstruct->hashEntries.find(curHash);
            if (hit == curInstruct->hashEntries.end()) continue;
            removeNGram(curInstruct, curHash);
            int newValue = curHash.value ^ block->getMatchHash();
            curHash = Hash(newValue, curHash.size);
            curInstruct->nGrams[j] = curHash;
            insertNGram(curHash, curInstruct);
        }
    }
}

void HashStore::extendMatch(int nGramSize, InstructHash* srcInstruct, NgramMatch* srcMatch,
                            InstructHash* destInstruct, NgramMatch* destMatch, HashCalculator* hashCalc) {
    srcMatch->block = srcInstruct->block;
    srcMatch->startindex = srcInstruct->index;
    srcMatch->endindex = srcMatch->startindex + nGramSize - 1;
    destMatch->block = destInstruct->block;
    destMatch->startindex = destInstruct->index;
    destMatch->endindex = destMatch->startindex + nGramSize - 1;

    while (srcMatch->startindex > 0 && destMatch->startindex > 0) {
        InstructHash* curSrcInstruct = srcMatch->block->instList[srcMatch->startindex - 1];
        InstructHash* curDestInstruct = destMatch->block->instList[destMatch->startindex - 1];
        if (curSrcInstruct->isMatched) break;
        if (curDestInstruct->isMatched) break;
        int srcVal = Hash::ALTERNATE_SEED;
        int destVal = Hash::ALTERNATE_SEED;
        srcVal = hashCalc->calcHash(srcVal, curSrcInstruct->instruction);
        destVal = hashCalc->calcHash(destVal, curDestInstruct->instruction);
        if (srcVal != destVal) break;
        srcMatch->startindex -= 1;
        destMatch->startindex -= 1;
    }

    int srcMax = static_cast<int>(srcMatch->block->instList.size()) - 1;
    int destMax = static_cast<int>(destMatch->block->instList.size()) - 1;
    while (srcMatch->endindex < srcMax && destMatch->endindex < destMax) {
        InstructHash* curSrcInstruct = srcMatch->block->instList[srcMatch->endindex + 1];
        InstructHash* curDestInstruct = destMatch->block->instList[destMatch->endindex + 1];
        if (curSrcInstruct->isMatched) break;
        if (curDestInstruct->isMatched) break;
        int srcVal = Hash::ALTERNATE_SEED;
        int destVal = Hash::ALTERNATE_SEED;
        srcVal = hashCalc->calcHash(srcVal, curSrcInstruct->instruction);
        destVal = hashCalc->calcHash(destVal, curDestInstruct->instruction);
        if (srcVal != destVal) break;
        srcMatch->endindex += 1;
        destMatch->endindex += 1;
    }
}

std::list<Instruction*> HashStore::getUnmatchedInstructions() {
    std::list<Instruction*> res;
    for (auto& pair : blockList_) {
        Block* block = pair.second;
        for (InstructHash* instHash : block->instList) {
            if (!instHash->isMatched)
                res.push_back(instHash->instruction);
        }
    }
    return res;
}

void HashStore::clearSort() {
    hashSort_.clear();
    matchSort_.clear();
    for (auto& pair : blockList_) {
        pair.second->clearSort();
    }
}

HashEntry* HashStore::getFirstEntry() {
    if (matchSort_.empty()) return nullptr;
    return *matchSort_.begin();
}

HashEntry* HashStore::getEntry(const Hash& hash) {
    auto it = hashSort_.find(hash);
    if (it == hashSort_.end()) return nullptr;
    return it->second;
}

Block* HashStore::getBlock(const Address& addr) {
    auto it = blockList_.find(addr);
    if (it == blockList_.end()) return nullptr;
    return it->second;
}

} // namespace ghidra
