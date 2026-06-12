#pragma once

#include <ghidra/Address.h>
#include <ghidra/Funcdata.h>
#include <ghidra/BlockGraph.h>
#include <ghidra/LoadImage.h>
#include <ghidra/Translate.h>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <set>
#include <cstdint>

namespace ghidra {

class PcodeOpAST;
class VarnodeAST;
class FuncCallSpecs;
class JumpTable;

class FlowInfo {
public:
    enum Flags {
        IGNORE_OUTOFBOUNDS = 1,
        IGNORE_UNIMPLEMENTED = 2,
        ERROR_OUTOFBOUNDS = 4,
        ERROR_UNIMPLEMENTED = 8,
        ERROR_REINTERPRETED = 0x10,
        ERROR_TOOMANYINSTRUCTIONS = 0x20,
        UNIMPLEMENTED_PRESENT = 0x40,
        BADDATA_PRESENT = 0x80,
        OUTOFBOUNDS_PRESENT = 0x100,
        REINTERPRETED_PRESENT = 0x200,
        TOOMANYINSTRUCTIONS_PRESENT = 0x400,
        POSSIBLE_UNREACHABLE = 0x1000,
        FLOW_FORINLINE = 0x2000,
        RECORD_JUMPLOADS = 0x4000
    };

    struct VisitStat {
        Address seqAddr;
        int4 time;
        int4 size;
    };

private:
    Funcdata& data;
    BlockGraph& bblocks;
    std::vector<FuncCallSpecs*>& callList;
    std::vector<Address> addrList;
    std::vector<PcodeOpAST*> tableList;
    std::map<Address, VisitStat> visited;
    int4 insnCount;
    int4 insnMax;
    Address baddr;
    Address eaddr;
    Address minaddr;
    Address maxaddr;
    uint4 flags;
    bool flowOverridePresent;

    bool processInstruction(const Address& curAddr, bool& startBasic);
    void fallthru();
    void collectEdges();
    void splitBasic();
    void connectBasic();
    void handleOutOfBounds(const Address& from, const Address& to);
    void newAddress(PcodeOpAST* from, const Address& to);

public:
    FlowInfo(Funcdata& d, BlockGraph& b, std::vector<FuncCallSpecs*>& q);
    FlowInfo(Funcdata& d, BlockGraph& b, std::vector<FuncCallSpecs*>& q, const FlowInfo& op2);

    void setRange(const Address& b, const Address& e) { baddr = b; eaddr = e; }
    void setMaximumInstructions(int4 max) { insnMax = max; }
    void setFlags(uint4 val) { flags |= val; }
    void clearFlags(uint4 val) { flags &= ~val; }

    void generateOps();
    void generateBlocks();

    int4 getSize() const { return static_cast<int4>(maxaddr.getOffset() - minaddr.getOffset()); }
    bool hasUnimplemented() const { return (flags & UNIMPLEMENTED_PRESENT) != 0; }
    bool hasBadData() const { return (flags & BADDATA_PRESENT) != 0; }
    bool hasOutOfBounds() const { return (flags & OUTOFBOUNDS_PRESENT) != 0; }
    bool hasReinterpreted() const { return (flags & REINTERPRETED_PRESENT) != 0; }
    bool hasTooManyInstructions() const { return (flags & TOOMANYINSTRUCTIONS_PRESENT) != 0; }
    bool isFlowForInline() const { return (flags & FLOW_FORINLINE) != 0; }
    bool doesJumpRecord() const { return (flags & RECORD_JUMPLOADS) != 0; }

    int4 getInstructionCount() const { return insnCount; }
    int4 getBlockCount() const { return bblocks.getNumBlocks(); }
    const std::vector<FuncCallSpecs*>& getCallList() const { return callList; }
};

} // namespace ghidra
