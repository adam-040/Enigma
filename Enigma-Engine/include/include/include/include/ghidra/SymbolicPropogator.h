#pragma once

#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/ContextEvaluator.h>
#include <ghidra/ContextEvaluatorAdapter.h>
#include <ghidra/DataType.h>
#include <ghidra/Instruction.h>
#include <ghidra/Function.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/RefType.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeContext.h>

#include <cstdint>
#include <stack>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <list>
#include <map>
#include <memory>

namespace ghidra {

class TaskMonitor;

/**
 * Value class representing a constant or register-relative value.
 */
class Value {
public:
    Value() : relativeRegister(nullptr), value(0) {}
    Value(Register* relReg, int64_t val) : relativeRegister(relReg), value(val) {}
    explicit Value(int64_t val) : relativeRegister(nullptr), value(val) {}

    int64_t getValue() const {
        if (isRegisterRelativeValue()) {
            int64_t off = value;
            int size = relativeRegister->getBitLength();
            off = (off << (64 - size)) >> (64 - size);
            return off;
        }
        return value;
    }

    bool isRegisterRelativeValue() const { return relativeRegister != nullptr; }
    Register* getRelativeRegister() const { return relativeRegister; }

private:
    Register* relativeRegister;
    int64_t value;
};

/**
 * Saved flow state for context stack.
 * Mirrors the Java `SavedFlowState` record.
 */
struct SavedFlowState {
    VarnodeContext* vContext;
    const FlowType* flowType;
    Address source;
    Address destination;
    int pcodeIndex;
    int continueAfterHittingFlow;

    SavedFlowState(VarnodeContext* vc, const FlowType* ft, const Address& src, const Address& dst,
                   int continueFlow)
        : vContext(vc), flowType(ft), source(src), destination(dst),
          pcodeIndex(0), continueAfterHittingFlow(continueFlow) {
        if (pcodeIndex != 0) vContext->pushMemState(true);
    }

    SavedFlowState(VarnodeContext* vc, const FlowType* ft, const Address& src, const Address& dst,
                   int pcodeIdx, int continueFlow)
        : vContext(vc), flowType(ft), source(src), destination(dst),
          pcodeIndex(pcodeIdx), continueAfterHittingFlow(continueFlow) {
        vContext->pushMemState(pcodeIndex != 0);
    }

    bool isContinueAfterHittingFlow() const {
        return continueAfterHittingFlow != NOT_CONTINUING_CURRRENTLY;
    }

    void restoreState() {
        vContext->popMemState();
    }

    static constexpr int NOT_CONTINUING_CURRRENTLY = -1;
};

class SymbolicPropogator {
public:
    static constexpr int64_t POINTER_MIN_BOUNDS = 0x100;
    static constexpr int MAX_EXACT_INSTRUCTIONS = 100;
    static constexpr int MAX_EXTRA_INSTRUCTION_FLOW = 16;
    static constexpr int LRU_SIZE = 4096;

    SymbolicPropogator(Program* program);
    SymbolicPropogator(Program* program, bool recordStartEndState);
    ~SymbolicPropogator();

    void setDebug(bool debug);

    // Main entry point
    AddressSet flowConstants(const Address& startAddr, const AddressSetView* restrictSet,
                             ContextEvaluator* eval, bool saveContext, TaskMonitor* monitor);

    // Value querying
    Value getRegisterValue(const Address& toAddr, Register* reg);
    Value getEndRegisterValue(const Address& toAddr, Register* reg);
    std::string getRegisterValueRepresentation(const Address& addr, Register* reg);

    void setRegister(const Address& addr, Register* stackReg);

    // Status
    VarnodeContext* getContext() const { return context; }
    Program* getProgram() const { return program; }
    bool isCanceled() const { return canceled; }
    AddressSet* getVisitedBody() { return &visitedBody; }
    bool encounteredBranch() const { return hitCodeFlow; }
    bool readExecutable() const { return readExecutableAddress; }

    // Reference check options
    void setParamRefCheck(bool enable) { checkForParamRefs = enable; }
    void setParamPointerRefCheck(bool enable) { checkForParamPointerRefs = enable; }
    void setReturnRefCheck(bool enable) { checkForReturnRefs = enable; }
    void setStoredRefCheck(bool enable) { checkForStoredRefs = enable; }

    // Cache lookup methods
    std::vector<PcodeOp*> getInstructionPcode(Instruction* instruction);
    Instruction* getInstructionAt(const Address& addr);
    Instruction* getInstructionContaining(const Address& addr);
    Function* getFunctionAt(const Address& addr);

    // Reference creation (public for callers)
    Address makeReference(VarnodeContext* varnodeContext, Instruction* instruction, int opIndex,
                          Varnode* vt, DataType* dataType, const RefType* refType,
                          int pcodeop, bool knownReference, TaskMonitor* monitor);
    Address makeReference(VarnodeContext* vContext, Instruction* instruction, int opIndex,
                          int64_t knownSpaceID, int64_t wordOffset, int size,
                          DataType* dataType, const RefType* refType, int pcodeop,
                          bool knownReference, bool preExisting, TaskMonitor* monitor);

protected:
    // Core flow analysis
    AddressSet flowConstants(const Address& startAddr, const AddressSetView* restrictSet,
                             ContextEvaluator* eval, VarnodeContext* vContext, TaskMonitor* monitor);
    AddressSet flowConstants(const Address& fromAddr, const Address& startAddr,
                             const AddressSetView* restrictSet, ContextEvaluator* eval,
                             VarnodeContext* vContext, TaskMonitor* monitor);

    // Initialization
    void initValidAddressSpaces();
    VarnodeContext* saveOffCurrentContext(const Address& startAddr);
    void setPointerMask(Program* program);

    // Pcode processing
    bool applyPcode(std::stack<SavedFlowState>& contextStack, VarnodeContext* vContext,
                     Instruction* instruction, int startIndex, int continueAfterHittingFlow,
                     TaskMonitor* monitor);

    // Flow helpers
    bool isSimpleFallThrough(const FlowType* instrFlow) const;
    bool checkSameInstructionRun(Instruction* instr);

    // Reference helpers
    Varnode* getConstantOrExternal(VarnodeContext* vContext, const Address& minInstrAddress,
                                    Varnode* val1);
    Varnode* getStoredLocation(VarnodeContext* vContext, Varnode* space, Varnode* offset,
                                Varnode* size);
    void addLoadStoreReference(VarnodeContext* vContext, Instruction* instruction, int pcodeType,
                                Varnode* refLocation, Varnode* targetSpaceID,
                                Varnode* assigningVarnode, const RefType* reftype,
                                bool knownReference, TaskMonitor* monitor);
    void addStoredReferences(VarnodeContext* vContext, Instruction* instruction,
                              Varnode* storageLocation, Varnode* valueToStore, TaskMonitor* monitor);
    void addParamReferences(Function* func, const Address& callTarget, Instruction* instruction,
                             VarnodeContext* varnodeContext, TaskMonitor* monitor);
    void addReturnReferences(Instruction* instruction, VarnodeContext* varnodeContext,
                              TaskMonitor* monitor);
    void createVariableStorageReference(Instruction* instruction, VarnodeContext* varnodeContext,
                                         TaskMonitor* monitor, void* conv, void* storage,
                                         DataType* dataType, int64_t callOffset);
    void makeVariableStorageReference(void* storage, Instruction* instruction,
                                       VarnodeContext* varnodeContext, TaskMonitor* monitor,
                                       int64_t callOffset, DataType* dataType,
                                       const Address& lastSetAddr, void* bval);
    void* getPointerDataTypeValue(DataType* dataType, const Address& lastSetAddr, void* bval);
    void* getReturnLocationStorage(Function* func);
    int findOperandWithVarnodeAssignment(Instruction* instruction, Varnode* assigningVarnode);
    int getReferenceSpaceID(Instruction* instruction, int64_t offset);
    Address evaluateReference(VarnodeContext* vContext, Instruction* instruction,
                               int64_t knownSpaceID, int64_t wordOffset, int size,
                               DataType* dataType, const RefType* refType, int pcodeop,
                               bool knownReference, const Address& target);
    bool evaluatePureDataRef(Instruction* instruction, int64_t wordOffset,
                              const RefType* refType, const Address& target);
    int findOpIndexForRef(VarnodeContext* vcontext, Instruction* instruction, int opIndex,
                           int64_t wordOffset, const RefType* refType);
    bool checkOffByOne(Register* reg, int64_t wordOffset);
    bool checkPossibleOffsetAddr(int64_t offset);

    // Function side effects
    void handleFunctionSideEffects(Instruction* instruction, const Address& target,
                                    TaskMonitor* monitor);
    int getFunctionPurge(Program* prog, Function* function);
    int getDefaultStackDepthChange(Program* prog, void* model, int depth);
    int addStackOverride(Program* prog, const Address& addr, int purge);
    Address resolveFunctionReference(const Address& addr);
    bool isBranch(PcodeOp* pcodeOp);

    // Call fixup injection
    std::vector<PcodeOp*> checkForCallFixup(Program* prog, Function* func, Instruction* instr);
    std::vector<PcodeOp*> checkForUponReturnCallMechanismInjection(Program* prog, Function* func,
                                                                     const Address& target,
                                                                     Instruction* instr);
    std::vector<PcodeOp*> injectPcode(const std::vector<PcodeOp*>& currentPcode, int pcodeIndex,
                                       const std::vector<PcodeOp*>& replacePcode);
    std::vector<PcodeOp*> doCallOtherPcodeInjection(Instruction* instr,
                                                      const std::vector<Varnode*>& ins,
                                                      Varnode* out);
    std::vector<PcodeOp*> checkSegmentCallOther(void* payload, Instruction* instr,
                                                  const std::vector<Varnode*>& ins, Varnode* out);
    void* findPcodeInjection(Program* prog, void* snippetLibrary, int64_t callOtherIndex);

    // Cache fields
    std::unordered_map<Address, std::vector<Address>> instructionFlowsCache;
    std::unordered_map<Address, std::vector<PcodeOp*>> pcodeCache;
    std::unordered_map<Address, Instruction*> instructionAtCache;
    std::unordered_map<Address, Instruction*> instructionContainingCache;
    std::unordered_map<Address, Function*> functionAtCache;
    std::unordered_map<int64_t, void*> injectPayloadCache;

    // Core state
    ContextEvaluator* evaluator = nullptr;
    Program* program;
    ProgramContext* programContext;
    ProgramContext* spaceContext;
    ProgramContext* savedProgramContext;
    ProgramContext* savedSpaceContext;
    bool canceled = false;
    bool readExecutableAddress = false;
    VarnodeContext* context;

    AddressSet visitedBody;
    bool hitCodeFlow = false;
    bool debug = false;
    bool recordStartEndState = false;

    int64_t pointerMask;
    int pointerSize;
    DataType* pointerSizedDT = nullptr;

    std::vector<AddressSpace*> memorySpaces;
    bool defaultSpacesAreTheSame = false;

    // Same-instruction run detection
    int lastFullHashCode = 0;
    int lastInstrCode = -1;
    int sameInstrCount = 0;

    // Reference check options
    bool checkForParamRefs = true;
    bool checkForParamPointerRefs = true;
    bool checkForReturnRefs = true;
    bool checkForStoredRefs = true;

private:
    std::vector<Address> getInstructionFlowsAsPcode(Instruction* instruction);
    void cacheInstruction(const Address& addr, Instruction* instr);
};

} // namespace ghidra
