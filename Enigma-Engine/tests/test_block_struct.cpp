/**
 * Enigma Engine - Structured Block Family Test
 * Smoke tests for the 14 Block* classes + BlockMap + CachedEncoder ported
 * from ghidra.program.model.pcode (W136 - Batch C).
 */
#include <ghidra/StructuredBlock.h>
#include <ghidra/CachedEncoder.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <iostream>
#include <cstring>

using namespace ghidra;

static int passed = 0, total = 0;
#define TEST(n, x) do { total++; if(x){std::cout<<"[PASS] "<<n<<"\n"<<std::flush;passed++;}else{std::cout<<"[FAIL] "<<n<<"\n"<<std::flush;} } while(0)

int main() {
    std::cout << "=== Structured Block Family Test ===\n";

    TEST("typeToName PLAIN", std::strcmp(StructuredBlock::typeToName(StructuredBlock::PLAIN), "plain") == 0);
    TEST("typeToName GRAPH", std::strcmp(StructuredBlock::typeToName(StructuredBlock::GRAPH), "graph") == 0);
    TEST("typeToName COPY", std::strcmp(StructuredBlock::typeToName(StructuredBlock::COPY), "plain") == 0);
    TEST("typeToName GOTO", std::strcmp(StructuredBlock::typeToName(StructuredBlock::GOTO), "goto") == 0);
    TEST("typeToName INFLOOP", std::strcmp(StructuredBlock::typeToName(StructuredBlock::INFLOOP), "infloop") == 0);
    TEST("typeToName NULL", StructuredBlock::typeToName(999) == nullptr);

    TEST("nameToType PLAIN", StructuredBlock::nameToType("plain") == StructuredBlock::PLAIN);
    TEST("nameToType GRAPH", StructuredBlock::nameToType("graph") == StructuredBlock::GRAPH);
    TEST("nameToType GOTO", StructuredBlock::nameToType("goto") == StructuredBlock::GOTO);
    TEST("nameToType IFGOTO", StructuredBlock::nameToType("ifgoto") == StructuredBlock::IFGOTO);
    TEST("nameToType PROPERIF", StructuredBlock::nameToType("properif") == StructuredBlock::PROPERIF);
    TEST("nameToType IFELSE", StructuredBlock::nameToType("ifelse") == StructuredBlock::IFELSE);
    TEST("nameToType INFLOOP", StructuredBlock::nameToType("infloop") == StructuredBlock::INFLOOP);
    TEST("nameToType WHILEDO", StructuredBlock::nameToType("whiledo") == StructuredBlock::WHILEDO);
    TEST("nameToType DOWHILE", StructuredBlock::nameToType("dowhile") == StructuredBlock::DOWHILE);
    TEST("nameToType SWITCH", StructuredBlock::nameToType("switch") == StructuredBlock::SWITCH);
    TEST("nameToType MULTIGOTO", StructuredBlock::nameToType("multigoto") == StructuredBlock::MULTIGOTO);
    TEST("nameToType LIST", StructuredBlock::nameToType("list") == StructuredBlock::LIST);
    TEST("nameToType COPY", StructuredBlock::nameToType("copy") == StructuredBlock::COPY);
    TEST("nameToType unknown", StructuredBlock::nameToType("zzz") == -1);

    StructuredBlock sb1;
    sb1.setIndex(5);
    TEST("setIndex/getIndex", sb1.getIndex() == 5);
    TEST("default type PLAIN", sb1.getType() == StructuredBlock::PLAIN);

    StructuredBlockGraph bg;
    TEST("BlockGraph type GRAPH", bg.getType() == StructuredBlock::GRAPH);
    TEST("BlockGraph size 0", bg.getSize() == 0);

    auto* leaf1 = new StructuredBlock();
    auto* leaf2 = new StructuredBlock();
    auto* leaf3 = new StructuredBlock();
    leaf1->setIndex(10);
    leaf2->setIndex(11);
    leaf3->setIndex(12);
    bg.addBlock(leaf1);
    bg.addBlock(leaf2);
    bg.addBlock(leaf3);
    TEST("BlockGraph size 3", bg.getSize() == 3);
    TEST("BlockGraph getBlock(1)", bg.getBlock(1) == leaf2);
    bg.setIndices();
    TEST("BlockGraph setIndices", (bg.getIndex() == 0 && leaf1->getIndex() == 0 &&
                                    leaf2->getIndex() == 1 && leaf3->getIndex() == 2));

    BlockCopy bc;
    TEST("BlockCopy type COPY", bc.getType() == StructuredBlock::COPY);
    TEST("BlockCopy ref null", bc.getRef() == nullptr);
    TEST("BlockCopy altIndex 0", bc.getAltIndex() == 0);
    TEST("BlockCopy start NO_ADDRESS", bc.getStart() == Address::NO_ADDRESS);

    BlockCondition bcond;
    TEST("BlockCondition type", bcond.getType() == StructuredBlock::CONDITION);
    TEST("BlockCondition default opcode", bcond.getOpcode() == PcodeOp::BOOL_AND);

    BlockGoto bgt;
    TEST("BlockGoto type", bgt.getType() == StructuredBlock::GOTO);
    TEST("BlockGoto default gototype 1", bgt.getGotoType() == 1);
    TEST("BlockGoto target null", bgt.getGotoTarget() == nullptr);
    bgt.setGotoTarget(leaf1);
    TEST("BlockGoto set target", bgt.getGotoTarget() == leaf1);

    BlockIfGoto big;
    TEST("BlockIfGoto type", big.getType() == StructuredBlock::IFGOTO);
    big.setGotoTarget(leaf2);
    TEST("BlockIfGoto set target", big.getGotoTarget() == leaf2);

    BlockMultiGoto bmg;
    TEST("BlockMultiGoto type", bmg.getType() == StructuredBlock::MULTIGOTO);
    TEST("BlockMultiGoto num targets 0", bmg.getNumTargets() == 0);
    bmg.addGotoTarget(leaf1);
    bmg.addGotoTarget(leaf2);
    TEST("BlockMultiGoto addGotoTarget", bmg.getNumTargets() == 2);
    TEST("BlockMultiGoto target 0", bmg.getTarget(0) == leaf1);
    TEST("BlockMultiGoto target 1", bmg.getTarget(1) == leaf2);

    TEST("BlockList type", BlockList().getType() == StructuredBlock::LIST);
    TEST("BlockProperIf type", BlockProperIf().getType() == StructuredBlock::PROPERIF);
    TEST("BlockIfElse type", BlockIfElse().getType() == StructuredBlock::IFELSE);
    TEST("BlockDoWhile type", BlockDoWhile().getType() == StructuredBlock::DOWHILE);
    TEST("BlockWhileDo type", BlockWhileDo().getType() == StructuredBlock::WHILEDO);
    TEST("BlockInfLoop type", BlockInfLoop().getType() == StructuredBlock::INFLOOP);
    TEST("BlockSwitch type", BlockSwitch().getType() == StructuredBlock::SWITCH);

    StructuredBlockGraph outer;
    StructuredBlockGraph* inner = new StructuredBlockGraph();
    auto* lf1 = new StructuredBlock();
    auto* lf2 = new StructuredBlock();
    inner->addBlock(lf1);
    inner->addBlock(lf2);
    outer.addBlock(inner);
    TEST("Nested BlockGraph getSize outer", outer.getSize() == 1);
    TEST("Nested BlockGraph getSize inner", outer.getBlock(0) == inner);
    TEST("Nested inner size", inner->getSize() == 2);

    outer.addEdge(lf1, lf2);
    TEST("addEdge in count", lf1->getOutSize() == 1);
    TEST("addEdge out count", lf2->getInSize() == 1);
    TEST("addEdge in 0", lf1->getOut(0) == lf2);
    TEST("addEdge out 0", lf2->getIn(0) == lf1);

    StructuredBlock* front = outer.getFrontLeaf();
    TEST("getFrontLeaf returns leaf", (front == lf1 || front == lf2));

    StructuredBlock* deep = lf2;
    int depth = outer.calcDepth(deep);
    TEST("calcDepth outer->lf2", depth == 2);

    MemoryCachedEncoder enc;
    TEST("CachedEncoder empty", enc.isEmpty() == true);
    enc.openElement(ELEM_BLOCK);
    enc.writeSignedInteger(ATTRIB_INDEX, 42);
    enc.closeElement(ELEM_BLOCK);
    TEST("CachedEncoder non-empty after write", enc.isEmpty() == false);
    TEST("CachedEncoder buffer non-empty", !enc.getBuffer().empty());

    std::cout << "=== " << passed << "/" << total << " tests passed ===\n";
    return (passed == total) ? 0 : 1;
}
