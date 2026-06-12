#pragma once

#include <ghidra/ProcessorContext.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ContextEvaluator.h>
#include <ghidra/DataType.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Instruction.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/Varnode.h>

#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <memory>
#include <map>

namespace ghidra {

class VarnodeContext : public ProcessorContext {
public:
    static constexpr int MaxCrossBuilds = 200;
    static constexpr const char* SUSPECT_CONST_NAME = "SuspectConst";

    VarnodeContext(Program* program, ProgramContext* programContext,
                   ProgramContext* spaceProgramContext, bool recordStartEndState);
    ~VarnodeContext() override;

    void setDebug(bool debugOn);
    bool getDebug() const;

    void setCurrentInstruction(Instruction* instr);
    Instruction* getCurrentInstruction(const Address& addr);

    void flowToAddress(const Address& fromAddr, const Address& toAddr);
    void flowStart(const Address& toAddr);
    void flowEnd(const Address& address);

    Varnode* getValue(Varnode* varnode, ContextEvaluator* evaluator);
    Varnode* getValue(Varnode* varnode, bool signed_, ContextEvaluator* evaluator);
    int64_t* getConstant(Varnode* vnode, ContextEvaluator* evaluator);
    Varnode* getVarnode(int spaceID, int64_t offset, int size);

    void putValue(Varnode* out, Varnode* result, bool mustClear);
    void propogateResults(bool clearContext);
    void propogateValue(Register* reg, Varnode* node, Varnode* val, const Address& address);

    Varnode* add(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);
    Varnode* subtract(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);
    Varnode* and_(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);
    Varnode* or_(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);
    Varnode* left(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);
    Varnode* right(Varnode* val1, Varnode* val2, ContextEvaluator* evaluator);

    Varnode* createVarnode(int64_t value, int spaceID, int size);
    Varnode* createConstantVarnode(int64_t value, int size);
    Varnode* getVarnode(Varnode* spaceVn, Varnode* offsetVn, int size, ContextEvaluator* evaluator);

    bool isConstant(Varnode* varnode) const;
    bool isSuspectConstant(Varnode* varnode) const;
    bool isRegister(Varnode* varnode) const;
    bool isSymbolicSpace(AddressSpace* space) const;
    bool isSymbolicSpace(int spaceID) const;
    bool isExternalSpace(int spaceID) const;
    bool isExternalSpace(AddressSpace* space) const;
    bool isStackSymbolicSpace(Varnode* varnode) const;
    bool isSymbol(Varnode* varnode) const;
    bool readExecutableCode() const;
    void setReadExecutableCode();
    void clearReadExecutableCode();

    Register* getRegister(Varnode* vnode) const;
    Register* getRegister(const std::string& name) const;
    Varnode* getRegisterVarnode(Register* reg);

    RegisterValue* getRegisterValue(Register* reg, const Address& toAddr);

    void copy(Varnode* out, Varnode* in, bool mustClear, ContextEvaluator* evaluator);
    Varnode* extendValue(Varnode* out, const std::vector<Varnode*>& in, bool sext, ContextEvaluator* evaluator);

    Varnode* getStackVarnode();
    Register* getStackRegister() const { return stackReg; }
    Varnode** getReturnVarnode(Function* func);
    Varnode** getKilledVarnodes(Function* func);
    std::vector<Address> getKnownFlowToAddresses(const Address& addr) const;
    Address getLastSetLocation(Varnode* vnode, const Address& bval);
    Address getLastSetLocation(Register* reg, const Address& bval);
    Varnode* getRegisterVarnodeValue(Register* reg, const Address& fromAddr, const Address& toAddr, bool useEndState);
    Varnode* getEndRegisterVarnodeValue(Register* reg, const Address& fromAddr, const Address& toAddr, bool useEndState);

    // ProcessorContext interface
    Register* getBaseContextRegister() override;
    std::vector<Register*> getRegisters() override;
    Register* getRegister(const std::string& name) override;
    uint64_t getValue(Register* reg, bool isSigned) const override;
    RegisterValue* getRegisterValue(Register* reg) const override;
    bool hasValue(Register* reg) const override;
    void setValue(Register* reg, uint64_t value) override;
    void setRegisterValue(RegisterValue* value) override;
    void clearRegister(Register* reg) override;

    // Branch state management
    void pushMemState(bool saveTempUniques);
    void popMemState();

    int getAddressSpace(const std::string& name, int bitSize);

    bool isReadOnly(const Address& addr);

    Program* getProgram() const { return program; }
    AddressFactory* getAddressFactory() const { return addrFactory; }
    int getBadSpaceIDValue() const { return BAD_SPACE_ID_VALUE; }
    int getBadOffsetSpaceID() const { return BAD_OFFSET_SPACEID; }
    int getSuspectOffsetSpaceID() const { return SUSPECT_OFFSET_SPACEID; }
    const Address& getBadAddress() const { return BAD_ADDRESS; }
    Varnode* getBadVarnode() { return &BAD_VARNODE; }

    bool debug;

protected:
    Varnode* getMemoryValue(std::map<Address, Varnode*>& valStore, Varnode* varnode, bool signed_);
    void putMemoryValue(std::map<Address, Varnode*>& valStore, Varnode* out, Varnode* value);

private:
    void setupValidSymbolicStackNames(Program* program);

    // Value storage
    std::map<Address, Varnode*> memoryVals;
    std::map<Address, Varnode*> regVals;
    std::map<Address, Varnode*> tempVals;
    std::map<Address, Varnode*> tempUniqueVals;
    bool keepTempUniqueValues = false;
    int maxUniqueBytes = 0;

    // Flow to/from tracking
    std::unordered_map<Address, std::vector<Address>> flowToFromLists;

    // Branch state stacks
    std::stack<std::map<Address, Varnode*>> memoryValsStack;
    std::stack<std::map<Address, Varnode*>> regValsStack;
    std::stack<std::map<Address, Varnode*>> uniqueValsStack;

    // Instruction start/end register states
    std::unordered_map<Address, std::map<Address, Varnode*>> addrStartState;
    std::unordered_map<Address, std::map<Address, Varnode*>> addrEndState;

    Program* program;
    Varnode* stackVarnode = nullptr;
    Register* stackReg = nullptr;
    std::unordered_set<std::string> validSymbolicStackNames;

    Address BAD_ADDRESS;
    Varnode BAD_VARNODE;
    int BAD_OFFSET_SPACEID;
    int SUSPECT_OFFSET_SPACEID;
    Address SUSPECT_ZERO_ADDRESS;
    int BAD_SPACE_ID_VALUE;

    bool hitDest = false;
    int pointerBitSize;
    int pointerSize;

    AddressFactory* addrFactory = nullptr;
    ProgramContext* programContext;

    Address currentAddress;
    Instruction* currentInstruction = nullptr;

    bool isBE = false;
    bool recordStartEndState = false;

    std::vector<Varnode*> allocatedVarnodes;
    Varnode* byteVarnodes[256] = {};
};

} // namespace ghidra
