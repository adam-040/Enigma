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

#include <map>
#include <set>
#include <list>
#include "ghidra/Address.h"
#include "ghidra/correlate/Hash.h"
#include "ghidra/correlate/HashEntry.h"

namespace ghidra {

class Function;
class Program;
class TaskMonitor;
class Block;
class InstructHash;
class HashCalculator;
class Instruction;
class CodeBlock;
class CancelledException;
class MemoryAccessException;

class HashStore {
public:
    struct NgramMatch {
        Block* block = nullptr;
        int startindex = 0;
        int endindex = 0;
    };

    HashStore(Function* a, TaskMonitor* mon);

    int getTotalInstructions() const { return totalInstructions_; }
    int numMatchedInstructions() const { return matchedInstructionCount_; }

    void calcHashes(int minLength, int maxLength, bool wholeBlock, bool matchOnly, HashCalculator* hashCalc);
    void insertHashes();
    void matchHash(NgramMatch* match, std::vector<Instruction*>& instResult, std::vector<CodeBlock*>& blockResult);

    static void extendMatch(int nGramSize, InstructHash* srcInstruct, NgramMatch* srcMatch,
                            InstructHash* destInstruct, NgramMatch* destMatch, HashCalculator* hashCalc);

    std::list<Instruction*> getUnmatchedInstructions();
    void clearSort();
    bool isEmpty() const { return matchSort_.empty(); }
    HashEntry* getFirstEntry();
    HashEntry* getEntry(const Hash& hash);
    Block* getBlock(const Address& addr);
    TaskMonitor* getMonitor() const { return monitor_; }

    void removeHash(HashEntry* hashEntry);

private:
    struct HashOrderComparator {
        bool operator()(const HashEntry* o1, const HashEntry* o2) const;
    };

    Program* program_;
    Function* function_;
    TaskMonitor* monitor_;
    std::map<Address, Block*> blockList_;
    std::map<Hash, HashEntry*> hashSort_;
    std::set<HashEntry*, HashOrderComparator> matchSort_;
    int matchedBlockCount_ = 0;
    int matchedInstructionCount_ = 0;
    int totalInstructions_ = 0;

    void initializeStructures();
    void createBlock(CodeBlock* codeBlock);
    void insertNGram(const Hash& curHash, InstructHash* instHash);
    void insertInstructionNGrams(InstructHash* instHash);
    void removeNGram(InstructHash* instHash, const Hash& curHash);
    void removeInstructionNGrams(InstructHash* instHash);
};

} // namespace ghidra
