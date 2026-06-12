#pragma once

#include <vector>
#include <string>
#include <memory>
#include <ghidra/Varnode.h>
#include <ghidra/Address.h>
#include <ghidra/Constructor.h>
#include <ghidra/ParserWalker.h>
#include <ghidra/SleighDebugLogger.h>

namespace ghidra {

class DecisionNode {
public:
    struct Pattern {
        std::vector<uint8_t> mask;
        std::vector<uint8_t> value;
        bool isMatch(ParserWalker* walker, SleighDebugLogger* debug) const { return false; }
    };

    DecisionNode() = default;

    Constructor* resolve(ParserWalker* walker, SleighDebugLogger* debug) { return nullptr; }

    const std::vector<Pattern*>& getPatterns() const { return patternList; }
    const std::vector<Constructor*>& getConstructors() const { return constructorList; }
    const std::vector<DecisionNode*>& getChildren() const { return children; }

private:
    std::vector<Pattern*> patternList;
    std::vector<Constructor*> constructorList;
    std::vector<DecisionNode*> children;
    bool contextDecision = false;
    int startBit = 0;
    int bitSize = 0;
};

} // namespace ghidra
