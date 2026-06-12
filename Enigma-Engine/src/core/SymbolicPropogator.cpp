#include <ghidra/SymbolicPropogator.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Reference.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/Varnode.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Language.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/FlowOverride.h>

#include <stack>
#include <unordered_set>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iostream>
#include <algorithm>

namespace ghidra {

// mask for sub-piece extraction (matching Java)
static int64_t maskSize[9] = {
    0xffLL, 0xffLL, 0xffffLL, 0xffffffLL, 0xffffffffLL, 0xffffffffffLL,
    0xffffffffffffLL, 0xffffffffffffffLL, static_cast<int64_t>(0xffffffffffffffffULL)
};

// ============================================================================
// Constructor / Destructor
// ============================================================================

SymbolicPropogator::SymbolicPropogator(Program* program_)
    : SymbolicPropogator(program_, true) {
}

SymbolicPropogator::SymbolicPropogator(Program* program_, bool recordStartEndState_)
    : program(program_),
      recordStartEndState(recordStartEndState_)
{
    Language* language = program->getLanguage();
    if (language) {
        const AddressFactory* af = language->getAddressFactory();
        (void)af;
    }
    programContext = nullptr;
    spaceContext = nullptr;
    setPointerMask(program);
    context = new VarnodeContext(program, programContext, spaceContext, recordStartEndState);
    context->setDebug(debug);
}

SymbolicPropogator::~SymbolicPropogator() {
    delete context;
    // programContext and spaceContext are not owned (or they're null)
}

void SymbolicPropogator::setDebug(bool debug_) {
    debug = debug_;
    if (context) context->setDebug(debug_);
}

void SymbolicPropogator::setPointerMask(Program* program_) {
    int ptrSize = program_->getDefaultPointerSize();
    if (ptrSize > 8) ptrSize = 8;
    pointerSize = ptrSize;
    pointerMask = maskSize[ptrSize];
    pointerSizedDT = nullptr;
}

// ============================================================================
// initValidAddressSpaces
// ============================================================================

void SymbolicPropogator::initValidAddressSpaces() {
    Language* language = program->getLanguage();
    if (!language) return;

    AddressSpace* defaultDataSpace = language->getDefaultDataSpace();
    AddressSpace* defaultspace = language->getDefaultSpace();
    defaultSpacesAreTheSame = (defaultspace->getSpaceID() == defaultDataSpace->getSpaceID());

    const AddressFactory* af = program->getAddressFactory();
    AddressSpace* defaultAddrSpace = const_cast<AddressSpace*>(af->getDefaultAddressSpace());

    memorySpaces.clear();
    auto spaces = af->getAddressSpaces();
    for (const AddressSpace* entry : spaces) {
        AddressSpace* space = const_cast<AddressSpace*>(entry);
        if (!space->isLoadedMemorySpace()) continue;

        if (space->isOverlaySpace()) {
            AddressSpace* baseSpace = space->getPhysicalSpace();
            if (baseSpace->getSpaceID() != defaultDataSpace->getSpaceID() &&
                baseSpace->getSpaceID() != defaultspace->getSpaceID()) {
                continue;
            }
        } else if (space->getSpaceID() != defaultDataSpace->getSpaceID() &&
                   space->getSpaceID() != defaultspace->getSpaceID()) {
            continue;
        }

        if (space->getSpaceID() == defaultAddrSpace->getSpaceID()) {
            memorySpaces.insert(memorySpaces.begin(), space);
        } else {
            memorySpaces.push_back(space);
        }
    }
}

// ============================================================================
// saveOffCurrentContext
// ============================================================================

VarnodeContext* SymbolicPropogator::saveOffCurrentContext(const Address& startAddr) {
    (void)startAddr;
    VarnodeContext* newContext = new VarnodeContext(program, nullptr, nullptr, recordStartEndState);
    newContext->setDebug(debug);
    return newContext;
}

// ============================================================================
// flowConstants - public entry point
// ============================================================================

AddressSet SymbolicPropogator::flowConstants(const Address& startAddr,
                                              const AddressSetView* restrictSet,
                                              ContextEvaluator* eval,
                                              bool saveContext,
                                              TaskMonitor* monitor)
{
    this->evaluator = eval;
    initValidAddressSpaces();

    savedProgramContext = programContext;
    savedSpaceContext = spaceContext;

    if (!saveContext) {
        context = saveOffCurrentContext(startAddr);
    }

    context->flowToAddress(Address::NO_ADDRESS, startAddr);

    context->propogateResults(false);

    AddressSet bodyDone;
    try {
        bodyDone = flowConstants(startAddr, restrictSet, eval, context, monitor);
    } catch (...) {
        programContext = savedProgramContext;
        spaceContext = savedSpaceContext;
        throw;
    }

    programContext = savedProgramContext;
    spaceContext = savedSpaceContext;
    readExecutableAddress = context->readExecutableCode();

    return bodyDone;
}

// ============================================================================
// flowConstants - internal with VarnodeContext
// ============================================================================

AddressSet SymbolicPropogator::flowConstants(const Address& startAddr,
                                              const AddressSetView* restrictSet,
                                              ContextEvaluator* eval,
                                              VarnodeContext* vContext,
                                              TaskMonitor* monitor)
{
    return flowConstants(Address::NO_ADDRESS, startAddr, restrictSet, eval, vContext, monitor);
}

AddressSet SymbolicPropogator::flowConstants(const Address& fromAddr,
                                              const Address& startAddr,
                                              const AddressSetView* restrictSet,
                                              ContextEvaluator* eval,
                                              VarnodeContext* vContext,
                                              TaskMonitor* monitor)
{
    visitedBody = AddressSet();
    std::unordered_set<Address> doNotFlowTo;

    std::stack<SavedFlowState> contextStack;
    contextStack.push(SavedFlowState(vContext, nullptr, fromAddr, startAddr,
                                     SavedFlowState::NOT_CONTINUING_CURRRENTLY));
    canceled = false;

    bool callCouldCauseBadStackDepth = false;
    if (program->getCompilerSpec() && program->getCompilerSpec()->getDefaultCallingConvention()) {
        callCouldCauseBadStackDepth =
            program->getCompilerSpec()->getDefaultCallingConvention()->getExtraPop() ==
            PrototypeModel::UNKNOWN_EXTRAPOP;
    }
    (void)callCouldCauseBadStackDepth;

    std::map<Address, std::unordered_set<Address>> visitedMap;

    while (!contextStack.empty()) {
        if (monitor && monitor->isCancelled()) return visitedBody;
        if (canceled) return visitedBody;

        SavedFlowState nextFlow = contextStack.top();
        contextStack.pop();

        bool justPopped = true;
        Address nextAddr = nextFlow.destination;
        Address flowFromAddr = nextFlow.source;
        const FlowType* flowType = nextFlow.flowType;
        int pcodeStartIndex = nextFlow.pcodeIndex;
        int continueAfterHittingFlow = nextFlow.continueAfterHittingFlow;
        nextFlow.restoreState();

        if (flowType != nullptr) {
            if (flowType->isCall()) {
                AddressSet savedBody = visitedBody;
                Function* func = getFunctionAt(nextAddr);
                if (func) {
                    flowConstants(nextFlow.source, nextAddr, &func->getBody(), eval, vContext, monitor);
                }
                visitedBody = savedBody;
                continue;
            }

            if (flowType->isJump() && !flowType->isConditional()) {
                Function* func = getFunctionAt(nextAddr);
                if (func != nullptr && !func->getBody().contains(startAddr)) {
                    vContext->flowStart(nextAddr);
                    handleFunctionSideEffects(getInstructionAt(flowFromAddr), nextAddr, monitor);
                    continue;
                }
            }
        }

        if (doNotFlowTo.find(nextAddr) != doNotFlowTo.end()) {
            continue;
        }

        auto visitIt = visitedMap.find(nextAddr);
        if (visitIt != visitedMap.end()) {
            if (visitIt->second.find(flowFromAddr) != visitIt->second.end()) {
                continue;
            }
            if (continueAfterHittingFlow == SavedFlowState::NOT_CONTINUING_CURRRENTLY) {
                continueAfterHittingFlow = 0;
            }
        } else {
            visitedMap[nextAddr] = std::unordered_set<Address>();
            if (continueAfterHittingFlow == SavedFlowState::NOT_CONTINUING_CURRRENTLY &&
                visitedBody.contains(nextAddr)) {
                continueAfterHittingFlow = 0;
            }
        }
        visitedMap[nextAddr].insert(flowFromAddr);

        vContext->flowToAddress(flowFromAddr, nextAddr);

        lastFullHashCode = 0;
        lastInstrCode = -1;
        sameInstrCount = 0;
        Address maxAddr;
        while (nextAddr.isValid()) {
            if (monitor && monitor->isCancelled()) return visitedBody;

            vContext->flowStart(nextAddr);

            if (!visitedBody.contains(nextAddr)) {
                continueAfterHittingFlow = SavedFlowState::NOT_CONTINUING_CURRRENTLY;
            }

            if (restrictSet != nullptr && !restrictSet->contains(nextAddr)) {
                break;
            }

            Instruction* instr = getInstructionAt(nextAddr);
            if (instr == nullptr) break;

            const FlowType* originalFlowType = instr->getFlowType();

            if (checkSameInstructionRun(instr)) {
                break;
            }

            Address minInstrAddress = instr->getMinAddress();
            maxAddr = instr->getMaxAddress();

            // Check for delay slots (simplified: just use length)
            int fallOff = instr->getDefaultFallThroughOffset();
            maxAddr = minInstrAddress.add(fallOff - 1);

            vContext->setCurrentInstruction(instr);

            if (evaluator != nullptr) {
                if (evaluator->evaluateContextBefore(vContext, instr)) {
                    return visitedBody;
                }
            }

            bool continueCurrentTrace = applyPcode(contextStack, vContext, instr,
                                                     pcodeStartIndex, continueAfterHittingFlow, monitor);
            pcodeStartIndex = 0;

            if (evaluator != nullptr) {
                if (evaluator->evaluateContext(vContext, instr)) {
                    return visitedBody;
                }
            }

            const FlowType* instrFlow = instr->getFlowType();
            if (originalFlowType != nullptr && instrFlow != nullptr &&
                *originalFlowType != *instrFlow && instrFlow->isCall()) {
                std::vector<Address> targets = getInstructionFlowsAsPcode(instr);
                for (const Address& target : targets) {
                    handleFunctionSideEffects(instr, target, monitor);
                    doNotFlowTo.insert(target);
                }
            }

            if (visitedBody.contains(minInstrAddress) && !justPopped) {
                if (continueAfterHittingFlow > SavedFlowState::NOT_CONTINUING_CURRRENTLY) {
                    continueAfterHittingFlow++;
                } else {
                    continueAfterHittingFlow = 0;
                }
                if (continueAfterHittingFlow >= MAX_EXTRA_INSTRUCTION_FLOW ||
                    (instrFlow && instrFlow->isCall())) {
                    break;
                }
            }

            visitedBody.addRange(minInstrAddress, maxAddr);
            justPopped = false;
            vContext->flowEnd(minInstrAddress);

            bool simpleFlow = isSimpleFallThrough(instrFlow);
            hitCodeFlow |= !simpleFlow;

            Address fallThru = instr->getFallThrough();
            nextAddr = Address();
            if (continueCurrentTrace && fallThru.isValid()) {
                nextAddr = fallThru;
            }
        }
    }

    return visitedBody;
}

// ============================================================================
// isSimpleFallThrough
// ============================================================================

bool SymbolicPropogator::isSimpleFallThrough(const FlowType* instrFlow) const {
    if (instrFlow == nullptr) return true;
    return !instrFlow->isCall() && !instrFlow->isJump() && !instrFlow->isTerminal() &&
           instrFlow->hasFallthrough();
}

// ============================================================================
// checkSameInstructionRun
// ============================================================================

bool SymbolicPropogator::checkSameInstructionRun(Instruction* instr) {
    // Simplified: just compare instruction address and length
    static Address lastAddr;
    static int lastLen = -1;
    static int count = 0;

    Address addr = instr->getAddress();
    int len = instr->getLength();

    if (addr.getOffset() == lastAddr.getOffset() && lastAddr.isValid() && len == lastLen) {
        count++;
        if (count > MAX_EXACT_INSTRUCTIONS) {
            count = 0;
            return true;
        }
    } else {
        count = 0;
        lastAddr = addr;
        lastLen = len;
    }
    return false;
}

// ============================================================================
// Cache Methods
// ============================================================================

std::vector<PcodeOp*> SymbolicPropogator::getInstructionPcode(Instruction* instruction) {
    Address addr = instruction->getAddress();
    auto it = pcodeCache.find(addr);
    if (it != pcodeCache.end()) return it->second;

    std::vector<PcodeOp*> ops = instruction->getPcode();
    pcodeCache[addr] = ops;
    return ops;
}

Instruction* SymbolicPropogator::getInstructionAt(const Address& addr) {
    auto it = instructionAtCache.find(addr);
    if (it != instructionAtCache.end() && it->second == nullptr) return nullptr;
    if (it != instructionAtCache.end()) return it->second;

    Listing* listing = program->getListing();
    Instruction* instr = listing ? listing->getInstructionAt(addr) : nullptr;
    cacheInstruction(addr, instr);
    return instr;
}

Instruction* SymbolicPropogator::getInstructionContaining(const Address& addr) {
    auto it = instructionContainingCache.find(addr);
    if (it != instructionContainingCache.end()) return it->second;

    Instruction* instr = getInstructionAt(addr);
    if (instr != nullptr) return instr;

    Listing* listing = program->getListing();
    instr = listing ? listing->getInstructionContaining(addr) : nullptr;
    instructionContainingCache[addr] = instr;
    return instr;
}

Function* SymbolicPropogator::getFunctionAt(const Address& addr) {
    auto it = functionAtCache.find(addr);
    if (it != functionAtCache.end()) return it->second;

    FunctionManager* fmgr = program->getFunctionManager();
    Function* func = fmgr ? fmgr->getFunctionAt(addr) : nullptr;
    functionAtCache[addr] = func;
    return func;
}

void SymbolicPropogator::cacheInstruction(const Address& addr, Instruction* instr) {
    instructionAtCache[addr] = instr;
    if (instr != nullptr) {
        instructionContainingCache[instr->getMaxAddress()] = instr;
        getInstructionPcode(instr);
    }
}

std::vector<Address> SymbolicPropogator::getInstructionFlowsAsPcode(Instruction* instruction) {
    Address addr = instruction->getAddress();
    auto it = instructionFlowsCache.find(addr);
    if (it != instructionFlowsCache.end()) return it->second;

    std::vector<Address> flows;
    for (Varnode* vn : instruction->getFlows()) {
        flows.push_back(vn->getAddress());
    }
    instructionFlowsCache[addr] = flows;
    return flows;
}

// ============================================================================
// applyPcode - the big pcode evaluation switch
// ============================================================================

bool SymbolicPropogator::applyPcode(std::stack<SavedFlowState>& contextStack,
                                     VarnodeContext* vContext,
                                     Instruction* instruction,
                                     int startIndex,
                                     int continueAfterHittingFlow,
                                     TaskMonitor* monitor)
{
    Address nextAddr;
    if (instruction == nullptr) return false;

    std::vector<PcodeOp*> ops = getInstructionPcode(instruction);
    if (ops.empty()) return true;

    Address minInstrAddress = instruction->getAddress();

    if (debug) {
        std::cerr << minInstrAddress.toString() << "   "
                  << instruction->toString() << "   "
                  << startIndex << std::endl;
    }

    std::unordered_set<Address> previousInjectionTarget;
    int mustClearAllUntil_PcodeIndex = -1;
    bool mustClearAll = false;
    bool injected = false;
    int ptype = 0;

    for (int pcodeIndex = startIndex; pcodeIndex < static_cast<int>(ops.size()); pcodeIndex++) {
        mustClearAll = pcodeIndex < mustClearAllUntil_PcodeIndex;

        PcodeOp* pcodeOp = ops[pcodeIndex];
        ptype = pcodeOp->getOpcode();
        Varnode* out = pcodeOp->getOutput();
        const std::vector<Varnode*>& in = pcodeOp->getInputs();

        Varnode* val1 = nullptr;
        Varnode* val2 = nullptr;
        Varnode* val3 = nullptr;
        Varnode* result = nullptr;
        int64_t* longVal1 = nullptr;
        int64_t* longVal2 = nullptr;
        int64_t lresult = 0;
        bool suspectOffset = false;
        Varnode* vt = nullptr;

        if (debug) {
            std::cerr << "   " << pcodeOp->toString() << std::endl;
        }

        try {
            switch (ptype) {
                case PcodeOp::COPY:
                    if (in.size() > 0) {
                        if (in[0]->isAddress()) {
                            AddressSpace* addressSpace = in[0]->getAddress().getAddressSpace();
                            if (!addressSpace->hasMappedRegisters() ||
                                program->getRegister(in[0]->getAddress()) == nullptr) {
                                makeReference(vContext, instruction, Reference::MNEMONIC, in[0],
                                              nullptr, &RefTypes::READ, ptype, true, monitor);
                            }
                        }
                        vContext->copy(out, in[0], mustClearAll, evaluator);
                    }
                    break;

                case PcodeOp::SEGMENTOP:
                    if (in.size() >= 3) {
                        Varnode* vval = context->getValue(in[2], evaluator);
                        if (vval && context->isSymbolicSpace(vval->getSpace())) {
                            vval = vContext->createVarnode(vval->getOffset(), vval->getSpace(), out->getSize());
                        }
                        vContext->putValue(out, vval, mustClearAll);
                    }
                    break;

                case PcodeOp::LOAD:
                    if (in.size() >= 2) {
                        Varnode* memVal = nullptr;
                        val1 = vContext->getValue(in[0], evaluator);
                        val2 = vContext->getValue(in[1], evaluator);
                        if (val1 && val2) {
                            suspectOffset = vContext->isSuspectConstant(val2);
                            vt = vContext->getVarnode(in[0], val2, out->getSize(), evaluator);
                            if (vt) {
                                addLoadStoreReference(vContext, instruction, ptype, vt, in[0], in[1],
                                                      &RefTypes::READ, !suspectOffset, monitor);
                                memVal = vContext->getValue(vt, evaluator);
                            }
                        }
                        vContext->putValue(out, memVal, mustClearAll);
                    }
                    break;

                case PcodeOp::STORE:
                    if (in.size() >= 3) {
                        Varnode* offs = vContext->getValue(in[1], true, evaluator);
                        Varnode* stLoc = nullptr;
                        if (offs) {
                            suspectOffset = vContext->isSuspectConstant(offs);
                            stLoc = getStoredLocation(vContext, in[0], offs, in[2]);
                        }
                        addLoadStoreReference(vContext, instruction, ptype, stLoc, in[0], in[1],
                                              &RefTypes::WRITE, !suspectOffset, monitor);
                        val3 = vContext->getValue(in[2], nullptr);
                        if (val3 && !injected) {
                            addStoredReferences(vContext, instruction, stLoc, val3, monitor);
                        }
                        vContext->putValue(stLoc, val3, mustClearAll);
                    }
                    break;

                case PcodeOp::BRANCHIND:
                    if (in.size() >= 1) {
                        val1 = vContext->getValue(in[0], evaluator);
                        if (val1) {
                            suspectOffset = vContext->isSuspectConstant(val1);
                            vt = getConstantOrExternal(vContext, minInstrAddress, val1);
                            if (vt) {
                                makeReference(vContext, instruction, -1, vt, nullptr,
                                              instruction->getFlowType(), ptype, !suspectOffset, monitor);
                            }
                        }
                        vContext->propogateResults(true);
                        if (evaluator && evaluator->evaluateDestination(vContext, instruction)) {
                            canceled = true;
                            return false;
                        }
                    }
                    break;

                case PcodeOp::CALLIND:
                case PcodeOp::CALL: {
                    Address target;
                    Function* func = nullptr;
                    val1 = (in.size() > 0) ? in[0] : nullptr;

                    if (ptype == PcodeOp::CALLIND) {
                        if (val1) {
                            val1 = vContext->getValue(val1, evaluator);
                            if (val1) {
                                if (vContext->isConstant(val1)) {
                                    suspectOffset = vContext->isSuspectConstant(val1);
                                    AddressSpace* addrSpace = instruction->getAddress().getAddressSpace();
                                    target = Address(const_cast<AddressSpace*>(addrSpace),
                                                     addrSpace->truncateOffset(val1->getOffset()));
                                } else if (val1->isAddress()) {
                                    target = resolveFunctionReference(val1->getAddress());
                                } else if (vContext->isExternalSpace(val1->getSpace())) {
                                    target = val1->getAddress();
                                }
                            }
                        }
                    } else {
                        if (val1) target = val1->getAddress();
                    }

                    if (target.isValid()) {
                        if (target.isMemoryAddress()) {
                            vContext->propogateResults(false);
                        }
                        func = getFunctionAt(target);
                    }

                    if (func && func->isInline()) {
                        contextStack.push(SavedFlowState(vContext, &RefTypes::FALL_THROUGH,
                                                          minInstrAddress, func->getEntryPoint(),
                                                          pcodeIndex + 1, continueAfterHittingFlow));
                        contextStack.push(SavedFlowState(vContext, &RefTypes::UNCONDITIONAL_CALL,
                                                          minInstrAddress, func->getEntryPoint(),
                                                          continueAfterHittingFlow));
                        return false;
                    }

                    handleFunctionSideEffects(instruction, target, monitor);
                    break;
                }

                case PcodeOp::CALLOTHER: {
                    std::vector<PcodeOp*> callOtherPcode = doCallOtherPcodeInjection(instruction, in, out);
                    if (!callOtherPcode.empty()) {
                        ops = injectPcode(ops, pcodeIndex, callOtherPcode);
                        pcodeIndex = -1;
                        injected = true;
                    } else if (out) {
                        vContext->putValue(out, vContext->getBadVarnode(), mustClearAll);
                    }
                    break;
                }

                case PcodeOp::BRANCH:
                    if (in.size() >= 1) {
                        if (in[0]->isConstant()) {
                            int sequenceOffset = static_cast<int>(in[0]->getOffset());
                            if (sequenceOffset < 0) {
                                pcodeIndex = static_cast<int>(ops.size());
                                break;
                            }
                            pcodeIndex += sequenceOffset - 1;
                            ptype = PcodeOp::UNIMPLEMENTED;
                            break;
                        }
                        if (!in[0]->isAddress()) break;
                        vContext->propogateResults(true);
                        AddressSpace* branchSpace = minInstrAddress.getAddressSpace();
                        Address targetAddr = Address(const_cast<AddressSpace*>(branchSpace), in[0]->getAddress().getOffset());
                        contextStack.push(SavedFlowState(vContext, &RefTypes::UNCONDITIONAL_JUMP,
                                                          minInstrAddress, targetAddr,
                                                          continueAfterHittingFlow));
                        return false;
                    }
                    break;

                case PcodeOp::CBRANCH:
                    if (in.size() >= 2) {
                        vt = nullptr;
                        bool internalBranch = in[0]->isConstant();
                        if (internalBranch) {
                            int sequenceOffset = static_cast<int>(in[0]->getOffset());
                            if ((pcodeIndex + sequenceOffset) >= static_cast<int>(ops.size())) {
                                vContext->propogateResults(false);
                            }
                        } else if (in[0]->isAddress()) {
                            vt = in[0];
                            vContext->propogateResults(false);
                        }

                        Varnode* condition = vContext->getValue(in[1], nullptr);
                        int64_t* condVal = nullptr;
                        if (condition) {
                            condVal = vContext->getConstant(condition, nullptr);
                        }

                        bool followFalse = evaluator ? evaluator->followFalseConditionalBranches() : false;
                        bool conditionMet = condVal && *condVal != 0;

                        if (conditionMet) {
                            if (internalBranch) {
                                int sequenceOffset = static_cast<int>(in[0]->getOffset());
                                if (sequenceOffset > 0) {
                                    if (followFalse) {
                                        contextStack.push(SavedFlowState(vContext, &RefTypes::FALL_THROUGH,
                                                                          minInstrAddress, minInstrAddress,
                                                                          pcodeIndex + 1, continueAfterHittingFlow));
                                    }
                                    pcodeIndex += sequenceOffset - 1;
                                } else if (!followFalse) {
                                    pcodeIndex = static_cast<int>(ops.size());
                                    break;
                                }
                            } else {
                                if (followFalse) {
                                    contextStack.push(SavedFlowState(vContext, &RefTypes::FALL_THROUGH,
                                                                      minInstrAddress, minInstrAddress,
                                                                      pcodeIndex + 1, continueAfterHittingFlow));
                                }
                                AddressSpace* condSpace = const_cast<AddressSpace*>(minInstrAddress.getAddressSpace());
                                nextAddr = Address(condSpace, in[0]->getAddress().getOffset());
                                contextStack.push(SavedFlowState(vContext, &RefTypes::CONDITIONAL_JUMP,
                                                                   minInstrAddress, nextAddr,
                                                                   continueAfterHittingFlow));
                                pcodeIndex = static_cast<int>(ops.size());
                                return false;
                            }
                        } else {
                            if (internalBranch) {
                                int sequenceOffset = static_cast<int>(in[0]->getOffset());
                                if (sequenceOffset > 0) {
                                    int internalIndex = pcodeIndex + sequenceOffset;
                                    if (followFalse) {
                                        contextStack.push(SavedFlowState(vContext, &RefTypes::FALL_THROUGH,
                                                                          minInstrAddress, minInstrAddress,
                                                                          internalIndex, continueAfterHittingFlow));
                                    }
                                } else if (!followFalse) {
                                    pcodeIndex = static_cast<int>(ops.size());
                                    break;
                                }
                            } else {
                                if (followFalse) {
                                    AddressSpace* condSpace2 = const_cast<AddressSpace*>(minInstrAddress.getAddressSpace());
                                    nextAddr = Address(condSpace2, in[0]->getAddress().getOffset());
                                    contextStack.push(SavedFlowState(vContext, &RefTypes::CONDITIONAL_JUMP,
                                                                       minInstrAddress, nextAddr,
                                                                       continueAfterHittingFlow));
                                }
                            }
                        }
                        if (condVal) delete condVal;
                    }
                    break;

                case PcodeOp::RETURN:
                    if (in.size() >= 1) {
                        val1 = vContext->getValue(in[0], evaluator);
                        if (val1 && evaluator &&
                            evaluator->evaluateReturn(val1, vContext, instruction)) {
                            canceled = true;
                            return false;
                        }
                        addReturnReferences(instruction, vContext, monitor);
                    }
                    break;

                case PcodeOp::INT_ZEXT:
                    if (in.size() >= 1) {
                        if (in[0]->isAddress()) {
                            makeReference(vContext, instruction, Reference::MNEMONIC, in[0],
                                          nullptr, &RefTypes::READ, ptype, true, monitor);
                        }
                        val1 = vContext->extendValue(out, in, false, evaluator);
                        vContext->putValue(out, val1, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_SEXT:
                    if (in.size() >= 1) {
                        if (in[0]->isAddress()) {
                            makeReference(vContext, instruction, Reference::MNEMONIC, in[0],
                                          nullptr, &RefTypes::READ, ptype, true, monitor);
                        }
                        val1 = vContext->extendValue(out, in, true, evaluator);
                        vContext->putValue(out, val1, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_ADD:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        if (val1 == nullptr) val1 = vContext->getBadVarnode();
                        val2 = vContext->getValue(in[1], false, evaluator);
                        if (val2 == nullptr) val2 = vContext->getBadVarnode();
                        result = vContext->add(val1, val2, evaluator);
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_SUB:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        result = vContext->subtract(val1, val2, evaluator);
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_CARRY:
                case PcodeOp::INT_SCARRY:
                case PcodeOp::INT_SBORROW:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            if (ptype == PcodeOp::INT_CARRY) {
                                uint64_t a = static_cast<uint64_t>(*longVal1);
                                uint64_t b = static_cast<uint64_t>(*longVal2);
                                lresult = (a + b < a) ? 1 : 0;
                            } else if (ptype == PcodeOp::INT_SCARRY) {
                                int64_t a = *longVal1;
                                int64_t b = *longVal2;
                                int64_t sum = a + b;
                                lresult = ((a >= 0 && b >= 0 && sum < 0) ||
                                           (a < 0 && b < 0 && sum >= 0)) ? 1 : 0;
                            } else {
                                uint64_t a = static_cast<uint64_t>(*longVal1);
                                uint64_t b = static_cast<uint64_t>(*longVal2);
                                lresult = (a < b) ? 1 : 0;
                            }
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_2COMP:
                    if (in.size() >= 1) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        if (longVal1) {
                            lresult = -(*longVal1);
                            int shift = (8 - in[0]->getSize()) * 8;
                            if (shift > 0) lresult = lresult & (0xffffffffffffffffLL >> shift);
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_NEGATE:
                    if (in.size() >= 1) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        if (longVal1) {
                            result = vContext->createConstantVarnode(~(*longVal1), in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_XOR:
                    if (in.size() >= 2) {
                        if (in[0]->isRegister() && *in[0] == *in[1]) {
                            result = vContext->createConstantVarnode(0, out->getSize());
                        } else {
                            val1 = vContext->getValue(in[0], false, evaluator);
                            val2 = vContext->getValue(in[1], false, evaluator);
                            longVal1 = vContext->getConstant(val1, evaluator);
                            longVal2 = vContext->getConstant(val2, evaluator);
                            if (longVal1 && longVal2) {
                                lresult = *longVal1 ^ *longVal2;
                                result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                            }
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_AND:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        result = vContext->and_(val1, val2, evaluator);
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_OR:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        result = vContext->or_(val1, val2, evaluator);
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_LEFT:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        result = vContext->left(val1, val2, evaluator);
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_RIGHT:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            lresult = static_cast<int64_t>(
                                static_cast<uint64_t>(*longVal1) >> (*longVal2 & 0x3f));
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_SRIGHT:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], true, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            lresult = *longVal1 >> (*longVal2 & 0x3f);
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_MULT:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], true, evaluator);
                        val2 = vContext->getValue(in[1], true, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            lresult = *longVal1 * *longVal2;
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_DIV:
                case PcodeOp::INT_SDIV:
                    if (in.size() >= 2) {
                        bool isSigned = (ptype == PcodeOp::INT_SDIV);
                        val1 = vContext->getValue(in[0], isSigned, evaluator);
                        val2 = vContext->getValue(in[1], isSigned, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2 && *longVal2 != 0) {
                            if (isSigned) {
                                lresult = *longVal1 / *longVal2;
                            } else {
                                lresult = static_cast<int64_t>(
                                    static_cast<uint64_t>(*longVal1) / static_cast<uint64_t>(*longVal2));
                            }
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_REM:
                case PcodeOp::INT_SREM:
                    if (in.size() >= 2) {
                        bool isSigned = (ptype == PcodeOp::INT_SREM);
                        val1 = vContext->getValue(in[0], isSigned, evaluator);
                        val2 = vContext->getValue(in[1], isSigned, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2 && *longVal2 != 0) {
                            if (isSigned) {
                                lresult = *longVal1 % *longVal2;
                            } else {
                                lresult = static_cast<int64_t>(
                                    static_cast<uint64_t>(*longVal1) % static_cast<uint64_t>(*longVal2));
                            }
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::SUBPIECE:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], true, evaluator);
                        val2 = vContext->getValue(in[1], true, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (val1 && longVal2) {
                            int64_t subbyte = 8 * (*longVal2);
                            if (vContext->isSymbol(val1) && subbyte == 0 &&
                                out->getSize() == instruction->getAddress().getPointerSize()) {
                                result = val1;
                            } else if (out->getSize() <= 8) {
                                longVal1 = vContext->getConstant(val1, evaluator);
                                if (longVal1) {
                                    lresult = (*longVal1 >> subbyte) & maskSize[out->getSize()];
                                    result = vContext->createConstantVarnode(lresult, out->getSize());
                                }
                            }
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::INT_LESS:
                case PcodeOp::INT_LESSEQUAL:
                case PcodeOp::INT_SLESS:
                case PcodeOp::INT_SLESSEQUAL:
                case PcodeOp::INT_EQUAL:
                case PcodeOp::INT_NOTEQUAL:
                    if (in.size() >= 2) {
                        bool isSigned = (ptype == PcodeOp::INT_SLESS || ptype == PcodeOp::INT_SLESSEQUAL);
                        val1 = vContext->getValue(in[0], isSigned, evaluator);
                        val2 = vContext->getValue(in[1], isSigned, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            switch (ptype) {
                                case PcodeOp::INT_LESS:
                                    lresult = (static_cast<uint64_t>(*longVal1) < static_cast<uint64_t>(*longVal2)) ? 1 : 0;
                                    break;
                                case PcodeOp::INT_LESSEQUAL:
                                    lresult = (static_cast<uint64_t>(*longVal1) <= static_cast<uint64_t>(*longVal2)) ? 1 : 0;
                                    break;
                                case PcodeOp::INT_SLESS:
                                    lresult = (*longVal1 < *longVal2) ? 1 : 0;
                                    break;
                                case PcodeOp::INT_SLESSEQUAL:
                                    lresult = (*longVal1 <= *longVal2) ? 1 : 0;
                                    break;
                                case PcodeOp::INT_EQUAL:
                                    lresult = (*longVal1 == *longVal2) ? 1 : 0;
                                    break;
                                case PcodeOp::INT_NOTEQUAL:
                                    lresult = (*longVal1 != *longVal2) ? 1 : 0;
                                    break;
                            }
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::BOOL_NEGATE:
                    if (in.size() >= 1) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        if (longVal1) {
                            lresult = (*longVal1 == 0) ? 1 : 0;
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::BOOL_XOR:
                case PcodeOp::BOOL_AND:
                case PcodeOp::BOOL_OR:
                    if (in.size() >= 2) {
                        val1 = vContext->getValue(in[0], false, evaluator);
                        val2 = vContext->getValue(in[1], false, evaluator);
                        longVal1 = vContext->getConstant(val1, evaluator);
                        longVal2 = vContext->getConstant(val2, evaluator);
                        if (longVal1 && longVal2) {
                            switch (ptype) {
                                case PcodeOp::BOOL_XOR: lresult = *longVal1 ^ *longVal2; break;
                                case PcodeOp::BOOL_AND: lresult = *longVal1 & *longVal2; break;
                                case PcodeOp::BOOL_OR:  lresult = *longVal1 | *longVal2; break;
                            }
                            result = vContext->createConstantVarnode(lresult, in[0]->getSize());
                        }
                        vContext->putValue(out, result, mustClearAll);
                    }
                    break;

                case PcodeOp::FLOAT_ADD:
                case PcodeOp::FLOAT_SUB:
                case PcodeOp::FLOAT_MULT:
                case PcodeOp::FLOAT_DIV:
                case PcodeOp::FLOAT_NEG:
                case PcodeOp::FLOAT_ABS:
                case PcodeOp::FLOAT_SQRT:
                case PcodeOp::FLOAT_INT2FLOAT:
                case PcodeOp::FLOAT_FLOAT2FLOAT:
                case PcodeOp::FLOAT_TRUNC:
                case PcodeOp::FLOAT_CEIL:
                case PcodeOp::FLOAT_FLOOR:
                case PcodeOp::FLOAT_ROUND:
                case PcodeOp::FLOAT_EQUAL:
                case PcodeOp::FLOAT_NOTEQUAL:
                case PcodeOp::FLOAT_LESS:
                case PcodeOp::FLOAT_LESSEQUAL:
                case PcodeOp::FLOAT_NAN:
                case PcodeOp::MULTIEQUAL:
                case PcodeOp::INDIRECT:
                case PcodeOp::PIECE:
                case PcodeOp::CAST:
                case PcodeOp::PTRADD:
                case PcodeOp::PTRSUB:
                case PcodeOp::CPOOLREF:
                case PcodeOp::NEW:
                case PcodeOp::INSERT:
                case PcodeOp::ZPULL:
                case PcodeOp::POPCOUNT:
                case PcodeOp::LZCOUNT:
                case PcodeOp::SPULL:
                default:
                    if (out) {
                        vContext->putValue(out, nullptr, false);
                    }
                    break;
            }
        } catch (...) {
            if (out) {
                vContext->putValue(out, nullptr, false);
            }
        }
    }

    vContext->propogateResults(true);
    return true;
}

// ============================================================================
// getConstantOrExternal
// ============================================================================

Varnode* SymbolicPropogator::getConstantOrExternal(VarnodeContext* vContext,
                                                     const Address& minInstrAddress,
                                                     Varnode* val1)
{
    if (!context->isExternalSpace(val1->getSpace())) {
        int64_t* lval = vContext->getConstant(val1, evaluator);
        if (lval == nullptr) return nullptr;
        int64_t val = *lval;
        delete lval;
        return vContext->getVarnode(minInstrAddress.getAddressSpace()->getSpaceID(), val, 0);
    }
    return val1;
}

// ============================================================================
// getStoredLocation
// ============================================================================

Varnode* SymbolicPropogator::getStoredLocation(VarnodeContext* vContext,
                                                 Varnode* space,
                                                 Varnode* offset,
                                                 Varnode* size)
{
    if (offset == nullptr || size == nullptr) return nullptr;
    return vContext->getVarnode(space, offset, size->getSize(), evaluator);
}

// ============================================================================
// handleFunctionSideEffects
// ============================================================================

void SymbolicPropogator::handleFunctionSideEffects(Instruction* instruction,
                                                     const Address& target,
                                                     TaskMonitor* monitor)
{
    Function* targetFunc = nullptr;
    if (target.isValid()) {
        targetFunc = getFunctionAt(target);
    }
    Address fallThruAddr = instruction->getFallThrough();

    if (!fallThruAddr.isValid() || !target.isValid() ||
        target.getOffset() != fallThruAddr.getOffset()) {

        if (checkForParamRefs && evaluator &&
            evaluator->evaluateReference(context, instruction, PcodeOp::UNIMPLEMENTED,
                                          target.isValid() ? target : Address::NO_ADDRESS, 0,
                                          nullptr, &RefTypes::UNCONDITIONAL_CALL)) {
            addParamReferences(targetFunc, target, instruction, context, monitor);
        }

        Varnode** returnVarnodes = context->getReturnVarnode(targetFunc);
        if (returnVarnodes) {
            for (int i = 0; returnVarnodes[i] != nullptr; i++) {
                context->putValue(returnVarnodes[i], context->getBadVarnode(), false);
            }
        }

        Varnode** killedVarnodes = context->getKilledVarnodes(targetFunc);
        if (killedVarnodes) {
            for (int i = 0; killedVarnodes[i] != nullptr; i++) {
                context->putValue(killedVarnodes[i], context->getBadVarnode(), false);
            }
        }
    }

    if (targetFunc && targetFunc->isInline()) return;

    if (targetFunc && targetFunc->hasNoReturn()) {
        context->propogateResults(false);
    }

    Varnode* outStack = context->getStackVarnode();
    if (outStack && (targetFunc == nullptr || !targetFunc->isInline())) {
        int purge = getFunctionPurge(program, targetFunc);
        purge = addStackOverride(program, instruction->getAddress(), purge);

        // simplified: just clear stack if unknown purge
        if (purge == -1 || purge == -2) {
            Varnode* curVal = nullptr;
            if (fallThruAddr.isValid()) {
                std::vector<Address> knownFlows = context->getKnownFlowToAddresses(fallThruAddr);
                for (const Address& flowAddr : knownFlows) {
                    curVal = context->getRegisterVarnodeValue(context->getStackRegister(),
                                                               flowAddr, fallThruAddr, false);
                    if (curVal) break;
                }
            }
            if (curVal) {
                context->putValue(outStack, curVal, false);
            } else if (instruction->getLength() != 1) {
                context->putValue(outStack, nullptr, false);
            }
        } else if (purge != 0) {
            Varnode* purgeVar = context->createConstantVarnode(purge, outStack->getSize());
            Varnode* stackVal = context->getValue(outStack, true, evaluator);
            Varnode* newVal = nullptr;
            if (stackVal) {
                newVal = context->add(stackVal, purgeVar, evaluator);
            }
            context->putValue(outStack, newVal, false);
        }
    }
}

// ============================================================================
// getFunctionPurge
// ============================================================================

int SymbolicPropogator::getFunctionPurge(Program* prog, Function* function) {
    if (function == nullptr) return -1; // UNKNOWN_STACK_DEPTH_CHANGE
    // Simplified: just return default
    return getDefaultStackDepthChange(prog, nullptr, -1);
}

int SymbolicPropogator::getDefaultStackDepthChange(Program* prog, void* model_, int depth) {
    (void)prog; (void)depth;
    PrototypeModel* model = static_cast<PrototypeModel*>(model_);
    if (model == nullptr) {
        if (program->getCompilerSpec() == nullptr) return -1;
        model = program->getCompilerSpec()->getDefaultCallingConvention();
    }
    if (model == nullptr) return -1;

    int callStackMod = model->getExtraPop();
    int callStackShift = model->getStackshift();
    if (callStackMod != PrototypeModel::UNKNOWN_EXTRAPOP) {
        return callStackShift;
    }
    return -1;
}

int SymbolicPropogator::addStackOverride(Program* prog, const Address& addr, int purge) {
    (void)prog; (void)addr;
    return purge;
}

// ============================================================================
// resolveFunctionReference
// ============================================================================

Address SymbolicPropogator::resolveFunctionReference(const Address& addr) {
    Address extAddr;
    ReferenceManager* rmgr = program->getReferenceManager();
    if (rmgr) {
        std::vector<Reference*> refs = rmgr->getReferencesFrom(addr);
        for (Reference* ref : refs) {
            if (ref->isExternalReference()) {
                extAddr = ref->getToAddress();
            } else if (ref->isMemoryReference()) {
                if (ref->getReferenceType()->isCall()) {
                    return ref->getToAddress();
                }
            }
        }
    }
    return extAddr;
}

// ============================================================================
// Reference methods
// ============================================================================

Address SymbolicPropogator::makeReference(VarnodeContext* varnodeContext,
                                           Instruction* instruction,
                                           int opIndex,
                                           Varnode* vt,
                                           DataType* dataType,
                                           const RefType* refType,
                                           int pcodeop,
                                           bool knownReference,
                                           TaskMonitor* monitor)
{
    if (!vt->isAddress() && !varnodeContext->isExternalSpace(vt->getSpace())) {
        if (evaluator) {
            evaluator->evaluateSymbolicReference(varnodeContext, instruction, vt->getAddress());
        }
        return Address();
    }

    return makeReference(varnodeContext, instruction, opIndex,
                          vt->getSpace(), vt->getWordOffset(),
                          vt->getSize(), dataType, refType,
                          pcodeop, knownReference, false, monitor);
}

Address SymbolicPropogator::makeReference(VarnodeContext* vContext,
                                           Instruction* instruction,
                                           int opIndex,
                                           int64_t knownSpaceID,
                                           int64_t wordOffset,
                                           int size,
                                           DataType* dataType,
                                           const RefType* refType,
                                           int pcodeop,
                                           bool knownReference,
                                           bool preExisting,
                                           TaskMonitor* monitor)
{
    (void)opIndex;
    int64_t spaceID = knownSpaceID;
    if (spaceID == -1) {
        spaceID = getReferenceSpaceID(instruction, wordOffset);
        if (spaceID == -1) return Address();
    }

    Address instructionAddress = instruction->getAddress();
    Address target;
    try {
        const AddressSpace* space = program->getAddressFactory()->getAddressSpace(static_cast<int>(spaceID));
        if (space == nullptr) return Address();

        if (space->isExternalSpace()) {
            target = Address(const_cast<AddressSpace*>(space), wordOffset);
        } else {
            if (!space->isLoadedMemorySpace()) return Address();
            if (wordOffset == 0) return Address();

            if (wordOffset < 0) {
                target = Address(const_cast<AddressSpace*>(space), space->truncateOffset(wordOffset));
            } else {
                target = Address(const_cast<AddressSpace*>(space), wordOffset);
            }

            wordOffset = target.getAddressableWordOffset();

            if (space->hasMappedRegisters() && program->getRegister(target) != nullptr) {
                return Address();
            }

            AddressSpace* instrSpace = const_cast<AddressSpace*>(instructionAddress.getAddressSpace());
            target = Address(instrSpace, target.getOffset());

            if (!knownReference && program->getMemory() &&
                program->getMemory()->getBlock(target) == nullptr) {
                if (!refType->isFlow() && program->getReferenceManager() &&
                    !program->getReferenceManager()->hasReferencesTo(target)) {
                    return Address();
                }
            }
        }

        if (refType->isCall() && !refType->isComputed()) {
            return Address();
        }

        target = evaluateReference(vContext, instruction, knownSpaceID, wordOffset,
                                    size, dataType, refType, pcodeop,
                                    knownReference, target);
        if (!target.isValid() || preExisting) return Address();

        if (refType->isData() &&
            !evaluatePureDataRef(instruction, wordOffset, refType, target)) {
            return Address();
        }
    } catch (...) {
        return Address();
    }

    // Simplified: just add operand reference
    instruction->addOperandReference(0, target, refType, SourceType::ANALYSIS);
    return target;
}

// ============================================================================
// addLoadStoreReference
// ============================================================================

void SymbolicPropogator::addLoadStoreReference(VarnodeContext* vContext,
                                                Instruction* instruction,
                                                int pcodeType,
                                                Varnode* refLocation,
                                                Varnode* targetSpaceID,
                                                Varnode* assigningVarnode,
                                                const RefType* reftype,
                                                bool knownReference,
                                                TaskMonitor* monitor)
{
    if (refLocation == nullptr) return;
    int opIndex = findOperandWithVarnodeAssignment(instruction, assigningVarnode);
    if (instruction->getFlowType()->isCall()) {
        makeReference(vContext, instruction, opIndex, refLocation, nullptr, reftype,
                      pcodeType, knownReference, monitor);
    } else {
        int spaceID = refLocation->getSpace();
        if (vContext->isSymbolicSpace(spaceID)) {
            if (!vContext->isStackSymbolicSpace(refLocation) && evaluator) {
                int64_t offset = refLocation->getOffset();
                Address constant = program->getAddressFactory()->getConstantAddress(offset);
                Address newTarget = evaluator->evaluateConstant(vContext, instruction,
                                                                 pcodeType, constant, 0,
                                                                 nullptr, reftype);
                if (newTarget.isValid()) {
                    makeReference(vContext, instruction, Reference::MNEMONIC,
                                  newTarget.getAddressSpace()->getSpaceID(),
                                  newTarget.getOffset(), 0, nullptr, &RefTypes::DATA,
                                  pcodeType, false, false, monitor);
                    return;
                }
            }
        }
        makeReference(vContext, instruction, opIndex, refLocation, nullptr, reftype,
                      pcodeType, knownReference, monitor);
    }
}

// ============================================================================
// addStoredReferences
// ============================================================================

void SymbolicPropogator::addStoredReferences(VarnodeContext* vContext,
                                              Instruction* instruction,
                                              Varnode* storageLocation,
                                              Varnode* valueToStore,
                                              TaskMonitor* monitor)
{
    if (!checkForStoredRefs) return;
    if (storageLocation && storageLocation->isRegister()) return;
    if (!vContext->isConstant(valueToStore)) return;

    int64_t valueOffset = valueToStore->getOffset();
    makeReference(vContext, instruction, -1, -1, valueOffset, 0, nullptr, &RefTypes::DATA,
                  PcodeOp::STORE, false, false, monitor);
}

// ============================================================================
// findOperandWithVarnodeAssignment
// ============================================================================

int SymbolicPropogator::findOperandWithVarnodeAssignment(Instruction* instruction,
                                                          Varnode* assigningVarnode)
{
    if (!assigningVarnode->isUnique()) return -1;
    std::vector<PcodeOp*> pcode = instruction->getPcode();
    for (int j = static_cast<int>(pcode.size()) - 1; j >= 0; j--) {
        Varnode* pcodeOut = pcode[j]->getOutput();
        if (pcodeOut && *assigningVarnode == *pcodeOut) {
            return 0;  // Simplified: return first operand
        }
    }
    return -1;
}

// ============================================================================
// getReferenceSpaceID
// ============================================================================

int SymbolicPropogator::getReferenceSpaceID(Instruction* instruction, int64_t offset) {
    if (offset <= 4 && offset >= -1) return -1;

    AddressSpace* defaultDataSpace = program->getLanguage()->getDefaultDataSpace();
    if (memorySpaces.size() == 1) {
        return defaultDataSpace->getSpaceID();
    }

    int realMemSpaceCnt = 0;
    int containingMemSpaceCnt = 0;
    Address containingAddr;
    int symbolTargetCnt = 0;
    Address symbolTarget;

    AddressSpace* instrSpace = instruction->getAddress().getAddressSpace();
    AddressSpace* defaultspace = program->getLanguage()->getDefaultSpace();

    if (instrSpace->isOverlaySpace() &&
        instrSpace->getPhysicalSpace()->getSpaceID() == defaultspace->getSpaceID()) {
        defaultspace = instrSpace;
    }

    for (AddressSpace* space : memorySpaces) {
        if (space->isOverlaySpace()) {
            if (space != instrSpace) continue;
        } else {
            ++realMemSpaceCnt;
        }

        Address addr(const_cast<AddressSpace*>(space), space->truncateOffset(offset));
        if (space->isOverlaySpace() && addr.getAddressSpace() != space) continue;

        if (space->hasMappedRegisters() && program->getRegister(addr) != nullptr) {
            if (!space->isOverlaySpace()) --realMemSpaceCnt;
            continue;
        }

        if (program->getMemory() && program->getMemory()->getBlock(addr) != nullptr) {
            containingMemSpaceCnt++;
            containingAddr = addr;
        }
        if (program->getReferenceManager()) {
            bool hasRefs = program->getReferenceManager()->hasReferencesTo(addr);
            bool hasSymbol = program->getSymbolTable() &&
                             program->getSymbolTable()->getPrimarySymbol(addr) != nullptr;
            if (hasRefs || hasSymbol) {
                symbolTargetCnt++;
                symbolTarget = addr;
            }
        }
    }

    if (containingMemSpaceCnt == 1 && containingAddr.isValid()) {
        return containingAddr.getAddressSpace()->getSpaceID();
    }
    if (symbolTargetCnt == 1 && symbolTarget.isValid()) {
        return symbolTarget.getAddressSpace()->getSpaceID();
    }
    if (realMemSpaceCnt != 1 && !defaultSpacesAreTheSame) return -1;
    return defaultDataSpace->getSpaceID();
}

// ============================================================================
// evaluateReference
// ============================================================================

Address SymbolicPropogator::evaluateReference(VarnodeContext* vContext,
                                               Instruction* instruction,
                                               int64_t knownSpaceID,
                                               int64_t wordOffset,
                                               int size,
                                               DataType* dataType,
                                               const RefType* refType,
                                               int pcodeop,
                                               bool knownReference,
                                               const Address& target)
{
    if (evaluator == nullptr) return target;

    if (knownSpaceID == -1 || !knownReference) {
        Address constant = program->getAddressFactory()->getConstantAddress(wordOffset);
        Address newTarget = evaluator->evaluateConstant(vContext, instruction, pcodeop,
                                                         constant, size, dataType, refType);
        if (!newTarget.isValid()) return Address();
        if (newTarget.getOffset() != constant.getOffset()) {
            return newTarget;
        }
    }

    if (!evaluator->evaluateReference(vContext, instruction, pcodeop,
                                       target, size, dataType, refType)) {
        return Address();
    }
    return target;
}

// ============================================================================
// evaluatePureDataRef
// ============================================================================

bool SymbolicPropogator::evaluatePureDataRef(Instruction* instruction,
                                              int64_t wordOffset,
                                              const RefType* refType,
                                              const Address& target)
{
    if (refType->isRead() || refType->isWrite()) return true;

    if (instruction->getFallThrough().isValid() || instruction->getFlowOverride() != FlowOverride::NONE) {
        int64_t fallAddrOffset = instruction->getAddress().getOffset() + instruction->getDefaultFallThroughOffset();
        if (fallAddrOffset == wordOffset) return false;
    }

    if (program->getMemory() && program->getMemory()->getBlock(target) != nullptr) {
        Instruction* targetInstr = getInstructionContaining(target);
        if (targetInstr) {
            Address disassemblyAddress = targetInstr->getAddress();
            if (targetInstr->getAddress() != disassemblyAddress) return false;
            Function* func = program->getFunctionManager()->getFunctionContaining(target);
            if (func && func->getEntryPoint() != disassemblyAddress) return false;
        }
    }
    return true;
}

// ============================================================================
// addParamReferences (stub)
// ============================================================================

void SymbolicPropogator::addParamReferences(Function* func, const Address& callTarget,
                                             Instruction* instruction,
                                             VarnodeContext* varnodeContext,
                                             TaskMonitor* monitor)
{
    (void)func; (void)callTarget; (void)instruction;
    (void)varnodeContext; (void)monitor;
}

void SymbolicPropogator::addReturnReferences(Instruction* instruction,
                                              VarnodeContext* varnodeContext,
                                              TaskMonitor* monitor)
{
    if (!checkForReturnRefs) return;
    Function* func = program->getFunctionManager()->getFunctionContaining(instruction->getAddress());
    void* returnLoc = getReturnLocationStorage(func);
    if (returnLoc == nullptr) return;
    createVariableStorageReference(instruction, varnodeContext, monitor, nullptr,
                                    returnLoc, nullptr, 0);
}

void SymbolicPropogator::createVariableStorageReference(Instruction* instruction,
                                                         VarnodeContext* varnodeContext,
                                                         TaskMonitor* monitor,
                                                         void* conv,
                                                         void* storage,
                                                         DataType* dataType,
                                                         int64_t callOffset)
{
    (void)instruction; (void)varnodeContext; (void)monitor;
    (void)conv; (void)storage; (void)dataType; (void)callOffset;
}

void SymbolicPropogator::makeVariableStorageReference(void* storage,
                                                       Instruction* instruction,
                                                       VarnodeContext* varnodeContext,
                                                       TaskMonitor* monitor,
                                                       int64_t callOffset,
                                                       DataType* dataType,
                                                       const Address& lastSetAddr,
                                                       void* bval)
{
    (void)storage; (void)instruction; (void)varnodeContext; (void)monitor;
    (void)callOffset; (void)dataType; (void)lastSetAddr; (void)bval;
}

void* SymbolicPropogator::getPointerDataTypeValue(DataType* dataType,
                                                   const Address& lastSetAddr,
                                                   void* bval)
{
    (void)dataType; (void)lastSetAddr; (void)bval;
    return nullptr;
}

void* SymbolicPropogator::getReturnLocationStorage(Function* func) {
    (void)func;
    return nullptr;
}

// ============================================================================
// Call fixup injection (stubs)
// ============================================================================

std::vector<PcodeOp*> SymbolicPropogator::checkForCallFixup(Program* prog,
                                                             Function* func,
                                                             Instruction* instr)
{
    (void)prog; (void)func; (void)instr;
    return {};
}

std::vector<PcodeOp*> SymbolicPropogator::checkForUponReturnCallMechanismInjection(
    Program* prog, Function* func, const Address& target, Instruction* instr)
{
    (void)prog; (void)func; (void)target; (void)instr;
    return {};
}

std::vector<PcodeOp*> SymbolicPropogator::injectPcode(
    const std::vector<PcodeOp*>& currentPcode, int pcodeIndex,
    const std::vector<PcodeOp*>& replacePcode)
{
    (void)pcodeIndex;
    return replacePcode;
}

std::vector<PcodeOp*> SymbolicPropogator::doCallOtherPcodeInjection(
    Instruction* instr, const std::vector<Varnode*>& ins, Varnode* out)
{
    (void)instr; (void)ins; (void)out;
    return {};
}

std::vector<PcodeOp*> SymbolicPropogator::checkSegmentCallOther(
    void* payload, Instruction* instr, const std::vector<Varnode*>& ins, Varnode* out)
{
    (void)payload; (void)instr; (void)ins; (void)out;
    return {};
}

void* SymbolicPropogator::findPcodeInjection(Program* prog, void* snippetLibrary,
                                              int64_t callOtherIndex)
{
    (void)prog; (void)snippetLibrary; (void)callOtherIndex;
    return nullptr;
}

// ============================================================================
// Value query methods
// ============================================================================

Value SymbolicPropogator::getRegisterValue(const Address& toAddr, Register* reg) {
    Varnode* val = context->getRegisterVarnodeValue(reg, Address::NO_ADDRESS, toAddr, true);
    if (val == nullptr) return Value(0);
    if (context->isConstant(val)) {
        return Value(val->getOffset());
    }
    AddressSpace* space = val->getAddress().getAddressSpace();
    if (space && space->getName().find("track_") == 0) {
        return Value(val->getOffset());
    }
    Register* relativeReg = program->getRegister(space ? space->getName() : "");
    if (relativeReg) {
        return Value(relativeReg, val->getOffset());
    }
    return Value(0);
}

Value SymbolicPropogator::getEndRegisterValue(const Address& toAddr, Register* reg) {
    Varnode* val = context->getEndRegisterVarnodeValue(reg, Address::NO_ADDRESS, toAddr, true);
    if (val == nullptr) return Value(0);
    if (context->isConstant(val)) {
        return Value(val->getOffset());
    }
    AddressSpace* space = val->getAddress().getAddressSpace();
    if (space && space->getName().find("track_") == 0) {
        return Value(val->getOffset());
    }
    Register* relativeReg = program->getRegister(space ? space->getName() : "");
    if (relativeReg) {
        return Value(relativeReg, val->getOffset());
    }
    return Value(0);
}

std::string SymbolicPropogator::getRegisterValueRepresentation(const Address& addr,
                                                                Register* reg) {
    Varnode* val = context->getRegisterVarnodeValue(reg, Address::NO_ADDRESS, addr, true);
    if (val == nullptr) return "-";
    if (val->isConstant()) {
        return std::to_string(val->getOffset());
    }
    AddressSpace* space = val->getAddress().getAddressSpace();
    if (space && space->getName().find("track_") == 0) {
        return reg->getName() + "+0x" + std::to_string(val->getOffset());
    }
    if (context->isSymbol(val)) {
        return space->getName() + " + " + std::to_string(val->getOffset());
    }
    return "-";
}

void SymbolicPropogator::setRegister(const Address& addr, Register* stackReg) {
    context->flowToAddress(Address::NO_ADDRESS, addr);
    int spaceID = context->getAddressSpace(stackReg->getName(), stackReg->getBitLength());
    Varnode* vnode = context->createVarnode(0, spaceID, stackReg->getBitLength() / 8);
    context->putValue(context->getRegisterVarnode(stackReg), vnode, false);
    context->propogateResults(false);
    context->flowEnd(addr);
}

// ============================================================================
// findOpIndexForRef / checkOffByOne (simplified stubs)
// ============================================================================

int SymbolicPropogator::findOpIndexForRef(VarnodeContext* vcontext,
                                           Instruction* instruction,
                                           int opIndex,
                                           int64_t wordOffset,
                                           const RefType* refType)
{
    (void)vcontext; (void)refType; (void)wordOffset;
    return opIndex; // simplified
}

bool SymbolicPropogator::checkOffByOne(Register* reg, int64_t wordOffset) {
    if (reg == nullptr) return false;
    int64_t val = context->getValue(reg, false);
    if (val == 0 && !context->hasValue(reg)) return false;
    int64_t lval = val & pointerMask;
    return (lval == wordOffset || (lval ^ wordOffset) == 1);
}

bool SymbolicPropogator::checkPossibleOffsetAddr(int64_t offset) {
    int64_t maxAddrOffset = pointerMask;
    if ((offset >= 0 && offset < POINTER_MIN_BOUNDS) ||
        (llabs(maxAddrOffset - offset) < POINTER_MIN_BOUNDS)) {
        return false;
    }
    return true;
}

bool SymbolicPropogator::isBranch(PcodeOp* pcodeOp) {
    if (pcodeOp->isAssignment()) return false;
    int opcode = pcodeOp->getOpcode();
    if (opcode == PcodeOp::STORE || opcode == PcodeOp::LOAD) return false;
    return true;
}

} // namespace ghidra
