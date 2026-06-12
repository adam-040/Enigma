#include <ghidra/ArmAnalyzer.h>
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
#include <ghidra/Scalar.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/Options.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/FunctionManager.h>

namespace ghidra {

namespace {

class ArmPropagationEvaluator : public ConstantPropagationContextEvaluator {
public:
    ArmPropagationEvaluator(TaskMonitor* monitor_, bool trustWriteMem_,
                             Program* program_, SymbolicPropogator* symEval_,
                             ArmAnalyzer* analyzer_, AddressSet* destSet_)
        : ConstantPropagationContextEvaluator(monitor_, trustWriteMem_),
          program_(program_), symEval_(symEval_), analyzer_(analyzer_),
          destSet(destSet_), taskMonitor(monitor_) {}

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        FlowType* ftype = instr->getFlowType();
        if (ftype->isComputed() && ftype->isJump()) {
            Register* pcReg = program_->getLanguage()->getProgramCounter();
            Varnode* pcVal = context->getRegisterVarnodeValue(
                pcReg, instr->getAddress(), instr->getAddress(), false);
            if (pcVal != nullptr) {
                if (isLinkRegister(context, pcVal) && !instr->getFlowType()->isTerminal()) {
                    instr->setFlowOverride(FlowOverride::RETURN);
                    program_->getReferenceManager()->removeAllReferencesFrom(instr->getAddress());
                }
            }

            Varnode* lrVal = context->getRegisterVarnodeValue(
                analyzer_->lrRegister, instr->getAddress(), instr->getAddress(), false);
            if (lrVal != nullptr) {
                if (context->isConstant(lrVal)) {
                    int64_t target = lrVal->getAddress().getOffset();
                    AddressSpace* space = const_cast<AddressSpace*>(instr->getAddress().getAddressSpace());
                    Address maxAddrPlus1(space, instr->getAddress().getOffset() + instr->getLength());
                    if (target == maxAddrPlus1.getOffset() && !instr->getFlowType()->isCall()) {
                        if (analyzer_->hasDataReferenceTo(program_, maxAddrPlus1)) {
                            return false;
                        }
                        if (instr->getFlowOverride() != FlowOverride::NONE) {
                            return false;
                        }
                        instr->setFlowOverride(FlowOverride::CALL);
                        analyzer_->doArmThumbDisassembly(program_, instr, context, maxAddrPlus1,
                                                          instr->getFlowType(), false, taskMonitor);
                        Function* f = program_->getFunctionManager()->getFunctionContaining(
                            instr->getMinAddress());
                        // fixupFunctionBody: function body already contains this instruction
                        (void)f;
                    }
                }
            }
        }
        return false;
    }

    bool evaluateReference(VarnodeContext* context, Instruction* instr, int pcodeop,
                            const Address& address, int size, DataType* dataType,
                            const RefType* refType) override {
        if (refType->isJump() && refType->isComputed() &&
            program_->getMemory()->getBlock(address) != nullptr &&
            address.getOffset() != 0) {
            if (instr->getMnemonicString().size() >= 2 &&
                instr->getMnemonicString().substr(0, 2) == "tb") {
                return false;
            }
            analyzer_->doArmThumbDisassembly(program_, instr, context, address,
                                              instr->getFlowType(), true, taskMonitor);
            ConstantPropagationContextEvaluator::evaluateReference(
                context, instr, pcodeop, address, size, dataType, refType);
            return !symEval_->encounteredBranch();
        }

        if (refType->isData() && program_->getMemory()->getBlock(address) != nullptr) {
            if (refType->isRead() || refType->isWrite()) {
                int numOperands = instr->getNumOperands();
                analyzer_->createDataType(instr, address);
                if (numOperands <= 2) {
                    instr->addOperandReference(instr->getNumOperands() - 1, address, refType,
                                                SourceType::ANALYSIS);
                    return false;
                }
                return true;
            } else if (pcodeop == PcodeOp::STORE) {
                AddressSpace* space = const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace());
                Address eightAfter(space, instr->getMinAddress().getOffset() + 8);
                if (eightAfter == address) {
                    return false;
                }
            }
        } else if (refType->isCall() && refType->isComputed() && !address.isExternalAddress()) {
            analyzer_->doArmThumbDisassembly(program_, instr, context, address,
                                              instr->getFlowType(), true, taskMonitor);
        }

        return ConstantPropagationContextEvaluator::evaluateReference(
            context, instr, pcodeop, address, size, dataType, refType);
    }

    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override {
        FlowType* flowType = instruction->getFlowType();
        if (!flowType->isJump()) return false;

        auto refs = program_->getReferenceManager()->getReferencesFrom(instruction->getAddress());
        if (refs.empty() ||
            (refs.size() == 1 && refs[0]->getReferenceType()->isData()) ||
            symEval_->encounteredBranch()) {
            destSet->addRange(instruction->getMinAddress(), instruction->getMinAddress());
        }
        return false;
    }

    bool evaluateReturn(const Varnode* retVN, VarnodeContext* context,
                         Instruction* instruction) override {
        if (instruction->getFlowOverride() != FlowOverride::NONE) {
            return false;
        }
        if (retVN != nullptr && context->isConstant(const_cast<Varnode*>(retVN))) {
            int64_t offset = retVN->getOffset();
            if (offset > 3 && offset != -1) {
                instruction->setFlowOverride(FlowOverride::BRANCH);
            }
        }
        return false;
    }

private:
    bool isLinkRegister(VarnodeContext* context, Varnode* pcVal) {
        return (pcVal->isRegister() &&
                pcVal->getAddress() == analyzer_->lrRegister->getAddress()) ||
               (context->isSymbol(pcVal) &&
                pcVal->getAddress().getAddressSpace()->getName() == analyzer_->lrRegister->getName() &&
                pcVal->getOffset() == 0);
    }

    Program* program_;
    SymbolicPropogator* symEval_;
    ArmAnalyzer* analyzer_;
    AddressSet* destSet;
    TaskMonitor* taskMonitor;
};

} // anonymous namespace

ArmAnalyzer::ArmAnalyzer()
    : ConstantPropagationAnalyzer("ARM") {
}

bool ArmAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    bool can = program->getLanguage()->getProcessor().getName() == "ARM";
    if (!can) return false;

    auto* ncThis = const_cast<ArmAnalyzer*>(this);
    ncThis->tmodeRegister = program->getRegister("TMode");
    ncThis->tbRegister = program->getRegister("ISAModeSwitch");
    ncThis->lrRegister = program->getRegister("lr");

    return true;
}

AddressSet ArmAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                       const AddressSetView* flowSet,
                                       SymbolicPropogator* symEval, TaskMonitor* monitor) {
    AddressSet destSet;

    ArmPropagationEvaluator eval(monitor, trustWriteMemOption, program, symEval, this, &destSet);
    eval.setTrustWritableMemory(trustWriteMemOption);
    eval.setMinSpeculativeOffset(minSpeculativeRefAddress);
    eval.setMaxSpeculativeOffset(maxSpeculativeRefAddress);
    eval.setMinStoreLoadOffset(minStoreLoadRefAddress);
    eval.setCreateComplexDataFromPointers(createComplexDataFromPointers);

    AddressSet resultSet = symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);

    if (recoverSwitchTables) {
        recoverSwitches(program, destSet, symEval, monitor);
    }

    return resultSet;
}

bool ArmAnalyzer::hasDataReferenceTo(Program* program, const Address& addr) {
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!refMgr->hasReferencesTo(addr)) return false;
    auto refsTo = refMgr->getReferencesTo(addr);
    for (Reference* ref : refsTo) {
        if (ref->getReferenceType()->isData()) return true;
    }
    return false;
}

AddressSet ArmAnalyzer::recoverSwitches(Program* program, const AddressSetView& destSet_,
                                          SymbolicPropogator* symEval, TaskMonitor* monitor) {
    AddressSet results;
    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    if (!memory || !symTable || !listing) return results;

    AddressRangeIterator* iter = destSet_.getAddressRanges(true);
    while (iter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Instruction* jumpInstr = listing->getInstructionAt(addr);
        if (!jumpInstr) continue;

        // Try to find a base address from register operands
        auto regs = jumpInstr->getOperandRegisters(0);
        if (regs.empty()) continue;

        // Scan potential table entries starting after the jump instruction
        Address scanStart;
        try {
            scanStart = addr.add(jumpInstr->getLength());
        } catch (...) {
            continue;
        }

        // Read potential 4-byte table entries
        int entrySize = 4;
        for (int i = 0; i < 64; ++i) {
            Address entryAddr;
            try {
                entryAddr = scanStart.add(i * entrySize);
            } catch (...) {
                break;
            }

            if (listing->getInstructionContaining(entryAddr)) break;

            uint8_t bytes[4] = {};
            MemoryBlock* blk = memory->getBlock(entryAddr);
            if (!blk) break;
            int read = blk->getBytes(entryAddr, bytes, 4);
            if (read != 4) break;

            uint64_t targetVal = static_cast<uint64_t>(bytes[0]) |
                (static_cast<uint64_t>(bytes[1]) << 8) |
                (static_cast<uint64_t>(bytes[2]) << 16) |
                (static_cast<uint64_t>(bytes[3]) << 24);

            if (targetVal == 0) break; // End of table

            Address targetAddr(addr.getAddressSpace(), static_cast<int64_t>(targetVal));
            if (!memory->getBlock(targetAddr)) break;

            std::string label = "switch_0x" + targetAddr.toString();
            symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
            results.add(targetAddr);
        }
    }
    return results;
}

int ArmAnalyzer::createDataType(Instruction* instr, const Address& address) {
    Program* prog = instr->getProgram();
    if (!prog->getListing()->isUndefined(address)) return 0;

    const std::string& mnemonic = instr->getMnemonicString();

    int charOff = 0;
    if (mnemonic.size() >= 5 &&
        (mnemonic.substr(0, 5) == "ldrex" || mnemonic.substr(0, 5) == "strex")) {
        charOff = 5;
    } else if (mnemonic.size() >= 4 &&
               (mnemonic.substr(0, 4) == "ldrs" || mnemonic.substr(0, 4) == "strs")) {
        charOff = 4;
    } else if (mnemonic.size() >= 3 &&
               (mnemonic.substr(0, 3) == "ldr" || mnemonic.substr(0, 3) == "str")) {
        charOff = 3;
    } else if (mnemonic.size() >= 2 &&
               (mnemonic.substr(0, 2) == "ld" || mnemonic.substr(0, 2) == "st")) {
        charOff = 2;
    } else if (mnemonic.size() >= 3 && mnemonic.substr(0, 3) == "tbh") {
        charOff = 2;
    } else if (mnemonic.size() >= 3 && mnemonic.substr(0, 3) == "tbb") {
        charOff = 2;
    } else if (mnemonic.size() >= 4 &&
               (mnemonic.substr(0, 4) == "vldr" || mnemonic.substr(0, 4) == "vstr")) {
        charOff = static_cast<int>(mnemonic.size()) - 2;
    }

    if (charOff <= 0) return 0;

    // Create a DWord data type at the referenced address
    Data* data = prog->getListing()->createData(address, &DWordDataType::dataType());
    if (data) return data->getLength();
    return 4;
}

Address ArmAnalyzer::flowArmThumb(Program* program, Instruction* instruction,
                                   VarnodeContext* context, const Address& target,
                                   FlowType* flowType, bool addReference) {
    if (!target.isValid()) return Address();

    int64_t bxOffset = target.getOffset();
    int64_t thumbMode = bxOffset & 0x1;

    AddressSpace* space = const_cast<AddressSpace*>(instruction->getMinAddress().getAddressSpace());
    Address addr(space, bxOffset & 0xfffffffe);

    Listing* listing = program->getListing();

    if (flowType != nullptr) {
        int opIndex = 0;
        if (addReference) {
            auto refsFrom = program->getReferenceManager()->getReferencesFrom(instruction->getAddress());
            bool foundRef = false;
            for (Reference* ref : refsFrom) {
                if (ref->getToAddress() == addr) {
                    foundRef = true;
                    break;
                }
            }
            if (!foundRef) {
                if (opIndex == -1) {
                    instruction->addOperandReference(0, addr, flowType, SourceType::ANALYSIS);
                } else {
                    instruction->addOperandReference(opIndex, addr, flowType, SourceType::ANALYSIS);
                }
            }
        }
    }

    if (tmodeRegister != nullptr && listing->isUndefined(addr)) {
        bool inThumbMode = false;
        RegisterValue* curvalue = context->getRegisterValue(tmodeRegister);
        if (curvalue != nullptr && curvalue->getValue().size() > 0) {
            inThumbMode = (static_cast<int>(curvalue->getUnsignedOffset()) == 1);
        }
        RegisterValue* tbvalue = context->getRegisterValue(tbRegister);
        if (tbvalue != nullptr && tbvalue->getValue().size() > 0) {
            inThumbMode = (static_cast<int>(tbvalue->getUnsignedOffset()) == 1);
        } else {
            if (instruction->getMnemonicString() == "blx" || thumbMode != 0) {
                inThumbMode = true;
            }
        }
        uint64_t thumbModeValue = inThumbMode ? 1 : 0;
        try {
            program->getProgramContext()->setValue(tmodeRegister, thumbModeValue, addr, addr);
        } catch (...) {
            // ignore context change
        }
        return addr;
    }

    return Address();
}

void ArmAnalyzer::doArmThumbDisassembly(Program* program, Instruction* instruction,
                                         VarnodeContext* context, const Address& target,
                                         FlowType* flowType, bool addRef, TaskMonitor* monitor) {
    if (!target.isValid()) return;

    Address result = flowArmThumb(program, instruction, context, target, flowType, addRef);
    if (!result.isValid()) return;

    MemoryBlock* block = program->getMemory()->getBlock(result);
    if (block == nullptr || !block->isExecute() || !block->isInitialized() ||
        block->isExternalBlock()) return;

    // Disassembler not yet available via this API.
    // TMode context value is already set by flowArmThumb above,
    // which enables subsequent analysis passes to disassemble correctly.
}

void ArmAnalyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    if (options.hasOption("Switch Table Recovery"))
        recoverSwitchTables = options.getBool("Switch Table Recovery");
}

} // namespace ghidra
