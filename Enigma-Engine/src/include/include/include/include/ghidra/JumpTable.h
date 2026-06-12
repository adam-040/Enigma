#pragma once

#include <ghidra/Types.h>
#include <ghidra/Address.h>
#include <vector>
#include <cstdint>

namespace ghidra {

class PcodeOpAST;
class Funcdata;

class JumpTable {
public:
    enum RecoveryMode {
        RECOVERED_FULL,
        RECOVERED_PARTIAL,
        RECOVERED_RANGED,
        NOT_RECOVERED
    };

    struct JumpSlot {
        Address targetAddr;
        int4 index;
        bool reachable;

        JumpSlot() : index(-1), reachable(false) {}
        JumpSlot(const Address& addr, int4 idx) : targetAddr(addr), index(idx), reachable(true) {}
    };

private:
    PcodeOpAST* branchIndOp;
    std::vector<JumpSlot> slots;
    Address tableAddr;
    int4 tableSize;
    int4 entrySize;
    RecoveryMode recoveryMode;
    bool isSwitch;

public:
    JumpTable(PcodeOpAST* branchInd);

    PcodeOpAST* getBranchIndOp() const { return branchIndOp; }
    const std::vector<JumpSlot>& getSlots() const { return slots; }
    int4 getNumSlots() const { return static_cast<int4>(slots.size()); }

    void setTableAddr(const Address& addr) { tableAddr = addr; }
    const Address& getTableAddr() const { return tableAddr; }

    void setTableSize(int4 size) { tableSize = size; }
    int4 getTableSize() const { return tableSize; }

    void setEntrySize(int4 size) { entrySize = size; }
    int4 getEntrySize() const { return entrySize; }

    void setRecoveryMode(RecoveryMode mode) { recoveryMode = mode; }
    RecoveryMode getRecoveryMode() const { return recoveryMode; }

    void setIsSwitch(bool val) { isSwitch = val; }
    bool isSwitchTable() const { return isSwitch; }

    void addSlot(const Address& target, int4 index);
    const JumpSlot* getSlot(int4 index) const;
    Address getTarget(int4 index) const;

    bool isRecovered() const { return recoveryMode != NOT_RECOVERED; }
    bool isReachable(int4 index) const;

    void clear();
};

class JumpTableAnalyzer {
private:
    Funcdata* funcData;
    std::vector<JumpTable*> tables;

public:
    JumpTableAnalyzer(Funcdata* fd);
    ~JumpTableAnalyzer();

    void analyze();
    int4 getNumTables() const { return static_cast<int4>(tables.size()); }
    JumpTable* getTable(int4 i) { return (i >= 0 && i < static_cast<int4>(tables.size())) ? tables[i] : nullptr; }
    const JumpTable* getTable(int4 i) const { return (i >= 0 && i < static_cast<int4>(tables.size())) ? tables[i] : nullptr; }

    JumpTable* findTableForOp(PcodeOpAST* op) const;
    void clear();
};

} // namespace ghidra
