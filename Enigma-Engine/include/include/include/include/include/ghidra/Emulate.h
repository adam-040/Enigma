#pragma once

#include <ghidra/Types.h>
#include <ghidra/Address.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Translate.h>
#include <ghidra/Funcdata.h>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <functional>


namespace ghidra {

class Emulate;

class EmulateCallback {
protected:
    Emulate* emulate;
public:
    EmulateCallback();
    virtual ~EmulateCallback() = default;
    virtual bool pcodeCallback(PcodeOp* op);
    virtual bool addressCallback(const Address& addr);
    void setEmulate(Emulate* emu);
};

class BreakTable {
protected:
    std::map<uint32_t, EmulateCallback*> pcodeCallbacks;
    std::map<Address, EmulateCallback*> addressCallbacks;
public:
    virtual ~BreakTable() = default;
    virtual void setEmulate(Emulate* emu);
    virtual bool doPcodeOpBreak(PcodeOp* op);
    virtual bool doAddressBreak(const Address& addr);
    void registerPcodeCallback(uint32_t opIndex, EmulateCallback* cb);
    void registerAddressCallback(const Address& addr, EmulateCallback* cb);
};

class Emulate {
protected:
    bool emuHalted;
    int currentOpcode;

    virtual void executeUnary() = 0;
    virtual void executeBinary() = 0;
    virtual void executeLoad() = 0;
    virtual void executeStore() = 0;
    virtual void executeBranch() = 0;
    virtual bool executeCbranch() = 0;
    virtual void executeBranchind() = 0;
    virtual void executeCall() = 0;
    virtual void executeCallind() = 0;
    virtual void executeCallother() = 0;
    virtual void executeMultiequal() = 0;
    virtual void executeIndirect() = 0;
    virtual void executeSegmentOp() = 0;
    virtual void executeCpoolRef() = 0;
    virtual void executeNew() = 0;
    virtual void fallthruOp() = 0;

public:
    Emulate();
    virtual ~Emulate() = default;

    void setHalt(bool val);
    bool getHalt() const;

    virtual void setExecuteAddress(const Address& addr) = 0;
    virtual Address getExecuteAddress() const = 0;

    void setCurrentOpcode(int opc) { currentOpcode = opc; }
    int getCurrentOpcode() const { return currentOpcode; }

    void executeCurrentOp();
};

class MemoryState {
public:
    struct MemoryBank {
        std::vector<uint8_t> data;
        uint64_t baseOffset;
        bool readOnly;

        MemoryBank() : baseOffset(0), readOnly(false) {}
        MemoryBank(uint64_t base, size_t size, bool ro = false)
            : baseOffset(base), readOnly(ro) { data.resize(size, 0); }
    };

private:
    std::map<std::string, MemoryBank> banks;
    std::map<std::string, uint64_t> registers;
    bool bigEndian;

public:
    MemoryState(bool be = false);

    void registerBank(const std::string& name, uint64_t base, size_t size, bool readOnly = false);
    void setRegister(const std::string& name, uint64_t value);
    uint64_t getRegister(const std::string& name) const;
    bool hasRegister(const std::string& name) const;

    void writeMemory(uint64_t addr, const uint8_t* data, size_t size);
    void readMemory(uint64_t addr, uint8_t* out, size_t size) const;

    uint64_t readValue(uint64_t addr, size_t size) const;
    void writeValue(uint64_t addr, uint64_t value, size_t size);

    uint64_t readValue(const std::string& regName, size_t size) const;
    void writeValue(const std::string& regName, uint64_t value, size_t size);

    bool isBigEndian() const { return bigEndian; }
    const std::map<std::string, MemoryBank>& getBanks() const { return banks; }
};

class EmulateMemory : public Emulate {
protected:
    MemoryState* memState;
    PcodeOp* currentOp;

    virtual void executeUnary();
    virtual void executeBinary();
    virtual void executeLoad();
    virtual void executeStore();
    virtual void executeBranch();
    virtual bool executeCbranch();
    virtual void executeBranchind();
    virtual void executeCall();
    virtual void executeCallind();
    virtual void executeCallother();
    virtual void executeMultiequal();
    virtual void executeIndirect();
    virtual void executeSegmentOp();
    virtual void executeCpoolRef();
    virtual void executeNew();

public:
    EmulateMemory(MemoryState* mem);
    MemoryState* getMemoryState() const { return memState; }
    PcodeOp* getCurrentOp() const { return currentOp; }
    void setCurrentOp(PcodeOp* op) { currentOp = op; }
};

class EmulatePcodeCache : public EmulateMemory {
private:
    Translate* translator;
    std::vector<PcodeOp*> opCache;
    std::vector<Varnode*> varCache;
    BreakTable* breakTable;
    Address currentAddress;
    bool instructionStart;
    int currentOpIndex;
    int instructionLength;

    void clearCache();
    void createInstruction(const Address& addr);
    void establishOp();

protected:
    virtual void fallthruOp();
    virtual void executeBranch();
    virtual void executeCallother();
    bool executeCbranch() override;

public:
    EmulatePcodeCache(Translate* t, MemoryState* s, BreakTable* b);
    ~EmulatePcodeCache() override;

    bool isInstructionStart() const { return instructionStart; }
    int numCurrentOps() const { return static_cast<int>(opCache.size()); }
    int getCurrentOpIndex() const { return currentOpIndex; }
    PcodeOp* getOpByIndex(int i) const;

    void setExecuteAddress(const Address& addr) override;
    Address getExecuteAddress() const override;

    void executeInstruction();

private:
    std::unique_ptr<Funcdata> currentFD_;
};


} // namespace ghidra
