#include <ghidra/MipsAddressAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/VarnodeContext.h>
#include <ghidra/Varnode.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Scalar.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/BookmarkType.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/Options.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/RefType.h>
#include <utility>

namespace ghidra {

namespace {

class MipsPropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    MipsPropagationEvaluator(TaskMonitor* monitor_, bool trustWriteMem_,
                              Program* program_, SymbolicPropogator* symEval_,
                              MipsAddressAnalyzer* analyzer_,
                              Address localGPAssumptionValue_, AddressSet& coveredSet_,
                              const AddressSetView* flowSet_)
        : ConstantPropagationContextEvaluator(monitor_, trustWriteMem_),
          program_(program_), symEval_(symEval_), analyzer_(analyzer_),
          localGPAssumptionValue(localGPAssumptionValue_), coveredSet_(coveredSet_),
          flowSet_(flowSet_), taskMonitor(monitor_) {}

    bool evaluateContextBefore(VarnodeContext* context, Instruction* instr) override {
        return mustStopNow;
    }

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        if (analyzer_->markupDualInstructionOption) {
            analyzer_->markupDualInstructions(context, instr, program_);
        }

        // if ra is a constant and is set right after this, this is a call
        Register* rareg = analyzer_->rareg;
        if (rareg) {
            uint64_t raVal = context->getValue(rareg, false);
            Varnode* raVn = context->getRegisterVarnode(rareg);
            if (raVn != nullptr && context->isConstant(raVn)) {
                int64_t target = static_cast<int64_t>(raVal);
                AddressSpace* space = const_cast<AddressSpace*>(instr->getAddress().getAddressSpace());
                Address maxAddr(space, instr->getAddress().getOffset() + instr->getLength() - 1);
                if (target == (maxAddr.getOffset() + 1) && !instr->getFlowType()->isCall()) {
                    instr->setFlowOverride(FlowOverride::CALL);
                    Address targetAddr(space, maxAddr.getOffset() + 1);
                    analyzer_->mipsExtDisassembly(program_, instr, context, targetAddr, taskMonitor);

                    Function* f = program_->getFunctionManager()->getFunctionContaining(
                        instr->getMinAddress());
                    if (f != nullptr) {
                        // fixupFunctionBody: function body already contains this instruction
                        (void)f;
                    }
                }
            }
        }

        // check if the GP register is set
        FlowType* flowType = instr->getFlowType();
        if (analyzer_->discoverGlobalGPSetting &&
            (flowType->isCall() || flowType->isTerminal())) {
            RegisterValue* registerValue = context->getRegisterValue(analyzer_->gp);
            if (registerValue != nullptr) {
                uint64_t unsignedValue = registerValue->getUnsignedOffset();
                if (localGPAssumptionValue.isValid() &&
                    unsignedValue == static_cast<uint64_t>(localGPAssumptionValue.getOffset())) {
                    // same value, nothing to do
                } else {
                    AddressSpace* iSpace = const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace());
                    Address gpRefAddr(iSpace, static_cast<int64_t>(unsignedValue));
                    analyzer_->setGPSymbol(program_, gpRefAddr);

                    AddressSpace* gpSpace = const_cast<AddressSpace*>(analyzer_->gp->getAddressSpace());
                    Address gpValueAddr(gpSpace, static_cast<int64_t>(unsignedValue));
                    Address lastSetAddr = context->getLastSetLocation(analyzer_->gp, gpValueAddr);
                    Instruction* lastSetInstr = instr;
                    if (lastSetAddr.isValid()) {
                        Instruction* instructionAt = program_->getListing()->getInstructionContaining(lastSetAddr);
                        if (instructionAt != nullptr) {
                            lastSetInstr = instructionAt;
                        }
                    }
                    if (lastSetAddr.isValid()) {
                        int64_t spaceId = static_cast<int64_t>(
                            reinterpret_cast<intptr_t>(
                                const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace())));
                        symEval_->makeReference(context, lastSetInstr, -1, spaceId,
                            unsignedValue, 1, nullptr, &RefTypes::DATA,
                            PcodeOp::UNIMPLEMENTED, true, false, taskMonitor);
                        if (!localGPAssumptionValue.isValid()) {
                            program_->getBookmarkManager()->setBookmark(
                                lastSetInstr->getMinAddress(),
                                "GP Global Register Set",
                                "Global GP Register is set here.");
                        }
                        if (localGPAssumptionValue.isValid() &&
                            localGPAssumptionValue != gpRefAddr) {
                            localGPAssumptionValue = Address();
                            analyzer_->gp_assumption_value = Address();
                        } else {
                            localGPAssumptionValue = gpRefAddr;
                            analyzer_->gp_assumption_value = gpRefAddr;
                        }
                    }
                }
            }
        }
        return mustStopNow;
    }

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        Address addr = address;
        if (!addr.isValid()) {
            return false;
        }

        if (instr->getMnemonicString().size() >= 3 &&
            instr->getMnemonicString().substr(instr->getMnemonicString().size() - 3) == "lui") {
            return false;
        }

        if ((refType->isJump() || refType->isCall()) && refType->isComputed()) {
            Address result = analyzer_->mipsExtDisassembly(program_, instr, context, address, taskMonitor);
            if (result.isValid()) {
                addr = result;
            }
        }

        if (refType->isCall() && !addr.isExternalAddress()) {
            if (instr->getFlowType()->isComputed()) {
                auto regs = instr->getOperandRegisters(0);
                if (!regs.empty()) {
                    Register* reg = regs[0];
                    if (analyzer_->t9 && *analyzer_->t9 == *reg && analyzer_->assumeT9EntryAddress) {
                        uint64_t val = context->getValue(reg, false);
                        if (val != 0 || context->getValue(reg, true) != 0) {
                            context->clearRegister(reg);
                            instr->addOperandReference(0, addr, instr->getFlowType(),
                                SourceType::ANALYSIS);
                            ProgramContext* progContext = program_->getProgramContext();
                            if (progContext && !progContext->getValue(reg, addr)) {
                                progContext->setValue(reg, val, addr, addr);
                                AutoAnalysisManager* amgr = AutoAnalysisManager::getAnalysisManager(program_);
                                if (amgr) {
                                    AddressSet addrSet;
                                    addrSet.addRange(addr, addr);
                                    amgr->codeDefined(addrSet);
                                }
                            }
                        }
                    }
                }
            }
        }

        return ConstantPropagationContextEvaluator::evaluateReference(
            context, instr, pcodeop, address, size, dataType, refType);
    }

    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override {
        FlowType* flowtype = instruction->getFlowType();
        if (!flowtype->isJump()) {
            return false;
        }
        if (analyzer_->trySwitchTables) {
            const std::string& mnemonic = instruction->getMnemonicString();
            if (mnemonic == "jr") {
                analyzer_->fixJumpTable(program_, instruction, taskMonitor);
            }
        }
        return false;
    }

    int64_t* unknownValue(VarnodeContext* context, Instruction* instruction,
                           const Varnode* node) override {
        if (analyzer_->assumeT9EntryAddress && node->isRegister()) {
            Varnode* t9Vn = context->getRegisterVarnode(analyzer_->t9);
            if (t9Vn && t9Vn->getAddress().getOffset() == node->getAddress().getOffset()) {
                Function* func = program_->getFunctionManager()->getFunctionContaining(
                    instruction->getAddress());
                if (func != nullptr) {
                    Address funcAddr = func->getEntryPoint();
                    int64_t value = funcAddr.getOffset();
                    ProgramContext* progContext = program_->getProgramContext();
                    if (progContext && !progContext->getValue(analyzer_->t9, funcAddr)) {
                        progContext->setValue(analyzer_->t9, static_cast<uint64_t>(value),
                                              funcAddr, funcAddr);
                        AutoAnalysisManager* amgr = AutoAnalysisManager::getAnalysisManager(program_);
                        if (amgr) {
                            coveredSet_.add(func->getBody());
                            amgr->codeDefined(coveredSet_);
                        }
                    } else {
                        return nullptr;
                    }
                }
                mustStopNow = true;
            }
        }
        return nullptr;
    }

private:
    Program* program_;
    SymbolicPropogator* symEval_;
    MipsAddressAnalyzer* analyzer_;
    Address localGPAssumptionValue;
    AddressSet& coveredSet_;
    const AddressSetView* flowSet_;
    TaskMonitor* taskMonitor;
    bool mustStopNow = false;
};

} // anonymous namespace

MipsAddressAnalyzer::MipsAddressAnalyzer()
    : ConstantPropagationAnalyzer("MIPS") {
}

bool MipsAddressAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    bool can = program->getLanguage()->getProcessor().getName() == "MIPS";
    if (!can) return false;

    const_cast<MipsAddressAnalyzer*>(this)->t9 = program->getRegister("t9");
    const_cast<MipsAddressAnalyzer*>(this)->gp = program->getRegister("gp");
    const_cast<MipsAddressAnalyzer*>(this)->rareg = program->getRegister("ra");
    const_cast<MipsAddressAnalyzer*>(this)->isamode = program->getRegister("ISA_MODE");
    const_cast<MipsAddressAnalyzer*>(this)->ismbit = program->getRegister("ISAModeSwitch");

    return true;
}

bool MipsAddressAnalyzer::added(Program* program, const AddressSetView& set,
                                 TaskMonitor* monitor, MessageLog& log) {
    gp_assumption_value = Address();
    checkForGlobalGP(program, set, monitor);
    return ConstantPropagationAnalyzer::added(program, set, monitor, log);
}

void MipsAddressAnalyzer::checkForGlobalGP(Program* program, const AddressSetView& set,
                                             TaskMonitor* monitor) {
    if (!discoverGlobalGPSetting) return;

    // check for _mips_gp_value symbol
    auto symbolsMipsGp = program->getSymbolTable()->getGlobalSymbols("_mips_gp_value");
    if (!symbolsMipsGp.empty()) {
        gp_assumption_value = symbolsMipsGp[0]->getAddress();
        return;
    }

    // check for _gp or _GP symbols
    auto symbolsGp = program->getSymbolTable()->getGlobalSymbols("_gp");
    if (symbolsGp.empty()) {
        symbolsGp = program->getSymbolTable()->getGlobalSymbols("_GP");
    }
    if (!symbolsGp.empty()) {
        gp_assumption_value = symbolsGp[0]->getAddress();
    }

    // check for _gp_1, _gp_2, etc.
    auto symbolsGp1 = program->getSymbolTable()->getGlobalSymbols("_gp_1");
    if (symbolsGp1.empty()) return;

    if (gp_assumption_value.isValid() &&
        symbolsGp1[0]->getAddress() == gp_assumption_value) {
        gp_assumption_value = Address();
        return;
    }

    auto symbolsGp2 = program->getSymbolTable()->getGlobalSymbols("_gp_2");
    if (symbolsGp2.empty()) {
        gp_assumption_value = symbolsGp1[0]->getAddress();
    }
}

Symbol* MipsAddressAnalyzer::setGPSymbol(Program* program, const Address& toAddr) {
    for (int index = 1; index < MAX_UNIQUE_GP_SYMBOLS; index++) {
        std::string symname = "_gp_" + std::to_string(index);
        auto existing = program->getSymbolTable()->getGlobalSymbols(symname);
        if (!existing.empty()) {
            if (existing[0]->getAddress() == toAddr) {
                return existing[0];
            }
            continue;
        }
        return program->getSymbolTable()->createLabel(toAddr, symname, SourceType::ANALYSIS);
    }
    return nullptr;
}

AddressSet MipsAddressAnalyzer::flowConstants(Program* program, const Address& flowStart_,
                                               const AddressSetView* flowSet,
                                               SymbolicPropogator* symEval,
                                               TaskMonitor* monitor) {
    const Function* func = program->getFunctionManager()->getFunctionContaining(flowStart_);
    AddressSet coveredSet;
    Address currentGPAssumptionValue = gp_assumption_value;
    Address flowStart = flowStart_;

    if (func != nullptr) {
        flowStart = func->getEntryPoint();
        if (currentGPAssumptionValue.isValid()) {
            ProgramContext* programContext = program->getProgramContext();
            RegisterValue* gpVal = programContext->getRegisterValue(gp, flowStart);
            if (gpVal == nullptr || gpVal->getValue().empty()) {
                gpVal = new RegisterValue(gp,
                    static_cast<uint64_t>(currentGPAssumptionValue.getOffset()),
                    gp->getMinimumByteSize());
                programContext->setRegisterValue(gpVal, func->getEntryPoint(), func->getEntryPoint());
            }
        }
    }

    MipsPropagationEvaluator eval(monitor, trustWriteMemOption, program, symEval,
                                   this, currentGPAssumptionValue, coveredSet, flowSet);
    eval.setTrustWritableMemory(trustWriteMemOption);
    eval.setMinSpeculativeOffset(minSpeculativeRefAddress);
    eval.setMaxSpeculativeOffset(maxSpeculativeRefAddress);
    eval.setMinStoreLoadOffset(minStoreLoadRefAddress);
    eval.setCreateComplexDataFromPointers(createComplexDataFromPointers);

    AddressSet resultSet = symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
    resultSet.add(coveredSet);

    return resultSet;
}

void MipsAddressAnalyzer::markupDualInstructions(VarnodeContext* context, Instruction* instr,
                                                   Program* program) {
    const std::string& mnemonic = instr->getMnemonicString();
    if (targetLoadStore.find(mnemonic) == targetLoadStore.end()) return;

    auto regs = instr->getOperandRegisters(0);
    if (regs.empty()) return;

    Register* reg = regs[0];
    uint64_t val = context->getValue(reg, false);
    if (val == 0 && context->getValue(reg, true) == 0) return;

    int64_t lval = static_cast<int64_t>(val);
    AddressSpace* space = const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace());
    Address refAddr(space, lval);

    if ((lval > 4096 || lval < 0) && lval != 0xffff &&
        program->getMemory()->getBlock(refAddr) != nullptr) {
        if (instr->getOperandReferences(0).empty()) {
            instr->addOperandReference(0, refAddr, &RefTypes::DATA, SourceType::ANALYSIS);
        }
    }
}

Address MipsAddressAnalyzer::mipsExtDisassembly(Program* program, Instruction* instruction,
                                                  VarnodeContext* context,
                                                  const Address& target, TaskMonitor* monitor) {
    if (!target.isValid() || target.isExternalAddress()) {
        return Address();
    }

    Address addr = flowISA(program, instruction, context, target);
    if (addr.isValid()) {
        MemoryBlock* block = program->getMemory()->getBlock(addr);
        if (block == nullptr || !block->isExecute() || !block->isInitialized() ||
            block->isExternalBlock()) {
            return addr;
        }
        // Disassembler not yet available via this API.
        // ISA_MODE context value is already set by flowISA above,
        // which enables subsequent analysis passes to disassemble correctly.
    }
    return addr;
}

Address MipsAddressAnalyzer::flowISA(Program* program, Instruction* instruction,
                                      VarnodeContext* context, const Address& target) {
    if (!target.isValid()) return Address();

    AddressSpace* space = const_cast<AddressSpace*>(instruction->getMinAddress().getAddressSpace());
    Address addr(space, target.getOffset() & 0xfffffffe);

    Listing* listing = program->getListing();
    if (isamode != nullptr && listing->isUndefined(addr)) {
        bool inM16Mode = false;
        RegisterValue* curvalue = context->getRegisterValue(isamode);
        if (curvalue != nullptr && curvalue->getValue().size() > 0) {
            inM16Mode = (static_cast<int>(curvalue->getUnsignedOffset()) == 1);
        }
        RegisterValue* tbvalue = context->getRegisterValue(ismbit);
        if (tbvalue != nullptr && tbvalue->getValue().size() > 0) {
            inM16Mode = (static_cast<int>(tbvalue->getUnsignedOffset()) == 1);
        }
        uint64_t m16ModeValue = inM16Mode ? 1 : 0;
        try {
            program->getProgramContext()->setValue(isamode, m16ModeValue, addr, addr);
        } catch (...) {
            // ignore context change
        }
        return addr;
    }
    return Address();
}

void MipsAddressAnalyzer::fixJumpTable(Program* program, Instruction* startInstr,
                                         TaskMonitor* monitor) {
    if (!program || !startInstr) return;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    if (!memory || !symTable || !listing) return;

    // Scan after the jump instruction for potential table entries
    Address scanStart;
    try {
        scanStart = startInstr->getMinAddress().add(startInstr->getLength());
    } catch (...) {
        return;
    }

    int entrySize = 4;
    int maxEntries = 64;
    for (int i = 0; i < maxEntries; ++i) {
        if (monitor && monitor->isCancelled()) break;

        Address entryAddr;
        try {
            entryAddr = scanStart.add(i * entrySize);
        } catch (...) {
            break;
        }

        if (listing->getInstructionContaining(entryAddr)) break;

        uint8_t bytes[4] = {};
        MemoryBlock* blk = memory->getBlock(entryAddr);
        if (!blk || blk->getBytes(entryAddr, bytes, 4) != 4) break;

        uint64_t targetVal = static_cast<uint64_t>(bytes[0]) |
            (static_cast<uint64_t>(bytes[1]) << 8) |
            (static_cast<uint64_t>(bytes[2]) << 16) |
            (static_cast<uint64_t>(bytes[3]) << 24);

        if (targetVal < 0x1000 || targetVal > 0xFFFFFFFF) break;

        Address targetAddr(scanStart.getAddressSpace(), static_cast<int64_t>(targetVal));
        if (!memory->getBlock(targetAddr)) break;

        std::string label = "jtable_" + std::to_string(i);
        symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
    }
}

bool MipsAddressAnalyzer::checkAlreadyRecovered(Program* program, const Address& addr) {
    int refCountFrom = program->getReferenceManager()->getReferenceCountFrom(addr);
    if (refCountFrom > 1) return true;

    auto refs = program->getReferenceManager()->getReferencesFrom(addr);
    if (refs.size() == 1 && !refs[0]->getReferenceType()->isData()) return true;

    return false;
}

void MipsAddressAnalyzer::registerOptions(Options& options, Program* program) {
    ConstantPropagationAnalyzer::registerOptions(options, program);
    options.registerBool("Attempt to recover switch tables", trySwitchTables,
                         "Attempt to recover switch tables");
    options.registerBool("Mark dual instruction references", markupDualInstructionOption,
                         "Turn on to mark all potential dual instruction refs");
    options.registerBool("Assume T9 set to Function entry", assumeT9EntryAddress,
                         "Turn on to assume that T9 is set to the entry address");
    options.registerBool("Recover global GP register writes", discoverGlobalGPSetting,
                         "Discover writes to the global GP register");
}

void MipsAddressAnalyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    if (options.hasOption("Attempt to recover switch tables"))
        trySwitchTables = options.getBool("Attempt to recover switch tables");
    if (options.hasOption("Mark dual instruction references"))
        markupDualInstructionOption = options.getBool("Mark dual instruction references");
    if (options.hasOption("Assume T9 set to Function entry"))
        assumeT9EntryAddress = options.getBool("Assume T9 set to Function entry");
    if (options.hasOption("Recover global GP register writes"))
        discoverGlobalGPSetting = options.getBool("Recover global GP register writes");
}

} // namespace ghidra
