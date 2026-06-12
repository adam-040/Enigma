#pragma once

#include <ghidra/Types.h>
#include <ghidra/Address.h>
#include <ghidra/VarnodeAST.h>
#include <ghidra/FunctionDefinition.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ghidra {

class PcodeOpAST;
class Funcdata;

class ParamTrial {
private:
    VarnodeAST* vn;
    bool active;
    bool persistent;
    int4 slot;

public:
    ParamTrial() : vn(nullptr), active(false), persistent(false), slot(-1) {}
    ParamTrial(VarnodeAST* v, int4 s) : vn(v), active(true), persistent(false), slot(s) {}

    VarnodeAST* getVarnode() const { return vn; }
    bool isActive() const { return active; }
    bool isPersistent() const { return persistent; }
    int4 getSlot() const { return slot; }

    void setActive(bool val) { active = val; }
    void setPersistent(bool val) { persistent = val; }
    void setSlot(int4 s) { slot = s; }
};

class ParamActive {
private:
    std::vector<ParamTrial> trials;
    int4 stackPlaceholderSlot;
    bool possibleOutput;

public:
    ParamActive() : stackPlaceholderSlot(-1), possibleOutput(false) {}

    void addTrial(VarnodeAST* vn, int4 slot);
    int4 numTrials() const { return static_cast<int4>(trials.size()); }
    ParamTrial* getTrial(int4 i) { return (i >= 0 && i < static_cast<int4>(trials.size())) ? &trials[i] : nullptr; }
    const ParamTrial* getTrial(int4 i) const { return (i >= 0 && i < static_cast<int4>(trials.size())) ? &trials[i] : nullptr; }

    void setStackPlaceholderSlot(int4 slot) { stackPlaceholderSlot = slot; }
    int4 getStackPlaceholderSlot() const { return stackPlaceholderSlot; }
    void freePlaceholderSlot() { stackPlaceholderSlot = -1; }

    bool isPossibleOutput() const { return possibleOutput; }
    void setPossibleOutput(bool val) { possibleOutput = val; }

    void clear();
};

class FuncCallSpecs {
private:
    PcodeOpAST* op;
    std::string name;
    Address entryAddress;
    Funcdata* fd;
    int4 effectiveExtraPop;
    uint64_t stackOffset;
    int4 stackPlaceholderSlot;
    int4 paramShift;
    int4 matchCallCount;
    ParamActive activeInput;
    ParamActive activeOutput;
    bool m_isInputActive;
    bool m_isOutputActive;
    bool m_isBadJumpTable;
    bool m_isStackOutputLock;

 public:
    enum {
        OFFSET_UNKNOWN = 0xBADBEEF
    };


    FuncCallSpecs(PcodeOpAST* callOp);

    void setAddress(const Address& addr) { entryAddress = addr; }
    PcodeOpAST* getOp() const { return op; }
    Funcdata* getFuncdata() const { return fd; }
    void setFuncdata(Funcdata* f) { fd = f; }
    FuncCallSpecs* clone(PcodeOpAST* newOp) const;

    const std::string& getName() const { return name; }
    void setName(const std::string& n) { name = n; }
    const Address& getEntryAddress() const { return entryAddress; }

    void setEffectiveExtraPop(int4 epop) { effectiveExtraPop = epop; }
    int4 getEffectiveExtraPop() const { return effectiveExtraPop; }
    uint64_t getSpacebaseOffset() const { return stackOffset; }
    void setSpacebaseOffset(uint64_t val) { stackOffset = val; }

    void setParamShift(int4 val) { paramShift = val; }
    int4 getParamShift() const { return paramShift; }
    int4 getMatchCallCount() const { return matchCallCount; }
    void setMatchCallCount(int4 val) { matchCallCount = val; }

    int4 getStackPlaceholderSlot() const { return stackPlaceholderSlot; }
    void setStackPlaceholderSlot(int4 slot) { stackPlaceholderSlot = slot; }

    void initActiveInput() { m_isInputActive = true; }
    void clearActiveInput() { m_isInputActive = false; }
    void initActiveOutput() { m_isOutputActive = true; }
    void clearActiveOutput() { m_isOutputActive = false; }
    bool isInputActive() const { return m_isInputActive; }
    bool isOutputActive() const { return m_isOutputActive; }

    void setBadJumpTable(bool val) { m_isBadJumpTable = val; }
    bool isBadJumpTable() const { return m_isBadJumpTable; }
    void setStackOutputLock(bool val) { m_isStackOutputLock = val; }
    bool isStackOutputLock() const { return m_isStackOutputLock; }


    ParamActive* getActiveInput() { return &activeInput; }
    ParamActive* getActiveOutput() { return &activeOutput; }
    const ParamActive* getActiveInput() const { return &activeInput; }
    const ParamActive* getActiveOutput() const { return &activeOutput; }

    static void countMatchingCalls(const std::vector<FuncCallSpecs*>& qlst);
};

} // namespace ghidra
