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
#include "ghidra/Address.h"
#include "ghidra/Duo.h"
#include "ghidra/ListingAddressCorrelation.h"
#include "ghidra/correlate/Hash.h"
#include "ghidra/correlate/HashEntry.h"

namespace ghidra {

class Function;
class AddressSetView;
class HashStore;
class InstructHash;
class HashCalculator;
class HashEntry;
class Instruction;
class CodeBlock;
class CancelledException;
class MemoryAccessException;
class TaskMonitor;
class DisambiguateStrategy;

class HashedFunctionAddressCorrelation : public ListingAddressCorrelation {
private:
    struct DisambiguatorEntry {
        Hash hash;
        int count;
        InstructHash* instruct;

        DisambiguatorEntry(const Hash& h, InstructHash* inst)
            : hash(h), count(1), instruct(inst) {}
    };

    Duo<Function*> functions_;
    std::map<Address, Address> srcToDest_;
    std::map<Address, Address> destToSrc_;
    HashStore* srcStore_;
    HashStore* destStore_;
    HashCalculator* hashCalc_;
    TaskMonitor* monitor_;

public:
    HashedFunctionAddressCorrelation(Function* leftFunction, Function* rightFunction, TaskMonitor* monitor);
    ~HashedFunctionAddressCorrelation() override;

    Program* getProgram(Side side) override;
    AddressSetView* getAddresses(Side side) override;
    Address getAddress(Side side, Address otherSideAddress) override;
    Function* getFunction(Side side) override;

    int getTotalInstructionsInFirst() const;
    int getTotalInstructionsInSecond() const;
    int numMatchedInstructionsInFirst() const;
    int numMatchedInstructionsInSecond() const;
    std::list<Instruction*> getUnmatchedInstructionsInFirst();
    std::list<Instruction*> getUnmatchedInstructionsInSecond();

private:
    void calculate();
    void runPasses(int minLength, int maxLength, bool wholeBlock, bool matchBlock, int maxPasses);
    void findMatches();
    bool disambiguateMatchingNgrams(HashEntry* srcEntry, HashEntry* destEntry);
    int disambiguateNgramsWithStrategy(DisambiguateStrategy* strategy, HashEntry* srcEntry, HashEntry* destEntry);
    static std::map<Hash, DisambiguatorEntry> constructDisambiguatorTree(HashEntry* entry, HashStore* store, DisambiguateStrategy* strategy);
    void declareMatch(HashEntry* srcEntry, InstructHash* srcInstruct, HashEntry* destEntry, InstructHash* destInstruct);
    void buildFinalMaps();
};

} // namespace ghidra
