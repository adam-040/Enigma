#include <ghidra/PowerPCAddressAnalyzer.h>
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
#include <ghidra/Scalar.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/Options.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/Relocation.h>

namespace ghidra {

namespace {

class PPCEvaluator : public ConstantPropagationContextEvaluator {
public:
    PPCEvaluator(TaskMonitor* monitor_, bool trustWriteMem_,
                  Program* program_, SymbolicPropogator* symEval_,
                  PowerPCAddressAnalyzer* analyzer_,
                  RegisterValue* startingR2Value_, bool isPEF_,
                  AddressSet* destSet_)
        : ConstantPropagationContextEvaluator(monitor_, trustWriteMem_),
          program_(program_), symEval_(symEval_), analyzer_(analyzer_),
          startingR2Value(startingR2Value_), isPEF(isPEF_),
          destSet(destSet_),           taskMonitor(monitor_), trustMem(trustWriteMem_) {}

    bool evaluateContextBefore(VarnodeContext* context, Instruction* instr) override {
        return false;
    }

    bool evaluateContext(VarnodeContext* context, Instruction* instr) override {
        if (analyzer_->markupDualInstructionOption) {
            analyzer_->markupDualInstructions(context, instr, program_);
        }

        Register* r2 = program_->getRegister("r2");
        Register* r30 = program_->getRegister("r30");

        if ((analyzer_->propagateR2value || analyzer_->propagateR30value) &&
            instr->getFlowType()->isCall()) {
            auto refs = program_->getReferenceManager()->getReferencesFrom(instr->getAddress());
            for (Reference* ref : refs) {
                Address destAddr = ref->getToAddress();
                if (analyzer_->propagateR2value && r2) {
                    if (!program_->getProgramContext()->getRegisterValue(r2, destAddr)) {
                        analyzer_->setRegisterIfNotSet(program_, destAddr, startingR2Value);
                    }
                }
                if (analyzer_->propagateR30value && r30) {
                    RegisterValue* r30Value = context->getRegisterValue(r30);
                    analyzer_->setRegisterIfNotSet(program_, destAddr, r30Value);
                }
            }
        }

        if (analyzer_->propagateR2value && isPEF &&
            analyzer_->isPEFCallingConvention(program_, instr)) {
            if (startingR2Value != nullptr && startingR2Value->getValue().size() > 0) {
                context->setRegisterValue(startingR2Value);
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
            ConstantPropagationContextEvaluator::evaluateReference(
                context, instr, pcodeop, address, size, dataType, refType);
            return !symEval_->encounteredBranch();
        }

        const std::string& mnemonic = instr->getMnemonicString();
        if (mnemonic == "li") {
            auto scalars = instr->getOperandScalars(1);
            if (!scalars.empty()) return false;
        }

        if (mnemonic == "lis") {
            return false;
        }

        if (mnemonic.size() >= 2 &&
            (mnemonic.substr(0, 2) == "ld" || mnemonic.substr(0, 2) == "lw" ||
             mnemonic.substr(0, 2) == "lb" || mnemonic.substr(0, 2) == "st")) {
            auto scalars = instr->getOperandScalars(1);
            for (Scalar* s : scalars) {
                if (s->getUnsignedValue() == static_cast<uint64_t>(address.getOffset())) {
                    return false;
                }
            }
        }

        return ConstantPropagationContextEvaluator::evaluateReference(
            context, instr, pcodeop, address, size, dataType, refType);
    }

    bool evaluateDestination(VarnodeContext* context, Instruction* instruction) override {
        const std::string& mnemonic = instruction->getMnemonicString();
        if (!instruction->getFlowType()->isJump()) {
            return false;
        }
        if (mnemonic == "bcctr" || mnemonic == "bcctrl" || mnemonic == "bctr") {
            if (!analyzer_->checkAlreadyRecovered(instruction->getProgram(),
                                                   instruction->getMinAddress())) {
                destSet->addRange(instruction->getMinAddress(), instruction->getMinAddress());
            }
        }
        return false;
    }

    int64_t* unknownValue(VarnodeContext* context, Instruction* instruction,
                           const Varnode* node) override {
        if (node->isRegister()) {
            Register* reg = program_->getRegister(node->getAddress());
            if (reg != nullptr) {
                if (reg->getName() == "xer_so") {
                    return new int64_t(0);
                }
                if (analyzer_->propagateR2value && reg->getName() == "r2" &&
                    startingR2Value != nullptr && startingR2Value->getValue().size() > 0) {
                    return new int64_t(static_cast<int64_t>(startingR2Value->getUnsignedOffset()));
                }
            }
        }
        return nullptr;
    }

    bool followFalseConditionalBranches() override {
        return true;
    }

    bool evaluateSymbolicReference(VarnodeContext* context, Instruction* instr,
                                    const Address& address) override {
        return false;
    }

    bool allowAccess(VarnodeContext* context, const Address& addr) override {
        return trustMem;
    }

private:
    Program* program_;
    SymbolicPropogator* symEval_;
    PowerPCAddressAnalyzer* analyzer_;
    RegisterValue* startingR2Value;
    bool isPEF;
    AddressSet* destSet;
    TaskMonitor* taskMonitor;
    bool trustMem;
};

} // anonymous namespace

PowerPCAddressAnalyzer::PowerPCAddressAnalyzer()
    : ConstantPropagationAnalyzer("PowerPC") {
}

bool PowerPCAddressAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "PowerPC";
}

bool PowerPCAddressAnalyzer::added(Program* program, const AddressSetView& set,
                                    TaskMonitor* monitor, MessageLog& log) {
    propagateR2value = getDefaultPropagateR2Option(program);
    propagateR30value = getDefaultPropagateR30Option(program);
    return ConstantPropagationAnalyzer::added(program, set, monitor, log);
}

AddressSet PowerPCAddressAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                                   const AddressSetView* flowSet,
                                                   SymbolicPropogator* symEval,
                                                   TaskMonitor* monitor) {
    RegisterValue* initR2Value = lookupR2(program, flowStart);
    bool isPEF = false; // PefLoader not ported
    AddressSet destSet;

    PPCEvaluator eval(monitor, trustWriteMemOption, program, symEval, this,
                       initR2Value, isPEF, &destSet);
    eval.setTrustWritableMemory(trustWriteMemOption);
    eval.setMinSpeculativeOffset(minSpeculativeRefAddress);
    eval.setMaxSpeculativeOffset(maxSpeculativeRefAddress);
    eval.setMinStoreLoadOffset(minStoreLoadRefAddress);
    eval.setCreateComplexDataFromPointers(createComplexDataFromPointers);

    AddressSet resultSet = symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);

    if (recoverSwitchTables) {
        recoverSwitches(program, symEval, destSet, monitor);
    }

    return resultSet;
}

void PowerPCAddressAnalyzer::setRegisterIfNotSet(Program* program, const Address& addr,
                                                   RegisterValue* regValue) {
    if (regValue == nullptr || regValue->getValue().empty()) return;
    if (regValue->getUnsignedOffset() == 0) return;

    ProgramContext* programContext = program->getProgramContext();
    RegisterValue* oldValue = programContext->getRegisterValue(regValue->getRegister(), addr);
    if (oldValue != nullptr && oldValue->getValue().size() > 0 &&
        oldValue->getUnsignedOffset() != 0) return;

    programContext->setRegisterValue(regValue, addr, addr);
    if (program->getFunctionManager()->getFunctionAt(addr) != nullptr) {
        AutoAnalysisManager* analysisMgr = AutoAnalysisManager::getAnalysisManager(program);
        if (analysisMgr) {
            analysisMgr->functionDefined(addr);
            analysisMgr->codeDefined(addr);
        }
    }
}

RegisterValue* PowerPCAddressAnalyzer::lookupR2(Program* program, const Address& flowStart) {
    if (!propagateR2value) return nullptr;

    Register* r2 = program->getRegister("r2");
    if (!r2) return nullptr;

    RegisterValue* initR2Value = program->getProgramContext()->getRegisterValue(r2, flowStart);
    if (initR2Value == nullptr || initR2Value->getValue().empty()) {
        initR2Value = findR2Value(program, flowStart);
        setRegisterIfNotSet(program, flowStart, initR2Value);
    }
    return initR2Value;
}

RegisterValue* PowerPCAddressAnalyzer::findR2Value(Program* program, const Address& start) {
    Register* r2 = program->getRegister("r2");
    if (!r2) return nullptr;

    // Check for _SDA_BASE_ symbol (ELF)
    auto sdaSymbols = program->getSymbolTable()->getGlobalSymbols("_SDA_BASE_");
    if (!sdaSymbols.empty()) {
        Address sdaAddr = sdaSymbols[0]->getAddress();
        uint64_t r2Val = static_cast<uint64_t>(sdaAddr.getOffset()) + 0x8000;
        return new RegisterValue(r2, r2Val, r2->getMinimumByteSize());
    }

    // Check for _SDA2_BASE_ symbol (ELF)
    auto sda2Symbols = program->getSymbolTable()->getGlobalSymbols("_SDA2_BASE_");
    if (!sda2Symbols.empty()) {
        Address sda2Addr = sda2Symbols[0]->getAddress();
        uint64_t r2Val = static_cast<uint64_t>(sda2Addr.getOffset()) + 0x8000;
        return new RegisterValue(r2, r2Val, r2->getMinimumByteSize());
    }

    // Check for .got2 section (ELF)
    MemoryBlock* got2Block = program->getMemory()->getBlock(".got2");
    if (got2Block) {
        uint64_t r2Val = static_cast<uint64_t>(got2Block->getStart().getOffset()) + 0x8000;
        return new RegisterValue(r2, r2Val, r2->getMinimumByteSize());
    }

    return nullptr;
}

RegisterValue* PowerPCAddressAnalyzer::findPefR2Value(Program* program, const Address& start) {
    Register* r2 = program->getRegister("r2");
    if (!r2) return nullptr;

    // For PEF, the r2 value is typically computed from the imported symbol table
    // Check for PEF-specific section names
    for (auto* block : program->getMemory()->getBlocks()) {
        std::string name = block->getName();
        if (name.find("PEF") != std::string::npos || name.find("pef") != std::string::npos) {
            uint64_t r2Val = static_cast<uint64_t>(start.getOffset()) & 0xFFFF0000;
            return new RegisterValue(r2, r2Val, r2->getMinimumByteSize());
        }
    }

    return nullptr;
}

bool PowerPCAddressAnalyzer::isPEFCallingConvention(Program* program, Instruction* instr) {
    if (instr->getMnemonicString() == "lwz") {
        auto regs = instr->getOperandRegisters(0);
        if (!regs.empty() && regs[0]->getName() == "r2") {
            auto scalars = instr->getOperandScalars(1);
            bool hasStackReg = false;
            bool hasOffset14 = false;
            for (Scalar* s : scalars) {
                if (s->getSignedValue() == 0x14) hasOffset14 = true;
            }
            auto opRegs = instr->getOperandRegisters(1);
            for (Register* r : opRegs) {
                Register* stackReg = program->getCompilerSpec()->getStackPointer();
                if (r != stackReg) return false;
                hasStackReg = true;
            }
            if (!hasStackReg || !hasOffset14) return false;

            Address fallAddr = instr->getFallFrom();
            Instruction* fallInstr = program->getListing()->getInstructionContaining(fallAddr);
            if (fallInstr != nullptr && fallInstr->getFlowType()->isCall()) {
                return true;
            }
        }
    }
    return false;
}

bool PowerPCAddressAnalyzer::checkAlreadyRecovered(Program* program, const Address& addr) {
    int refCountFrom = program->getReferenceManager()->getReferenceCountFrom(addr);
    if (refCountFrom > 1) return true;

    auto refs = program->getReferenceManager()->getReferencesFrom(addr);
    if (refs.size() == 1 && !refs[0]->getReferenceType()->isData()) return true;

    return false;
}

void PowerPCAddressAnalyzer::markupDualInstructions(VarnodeContext* context, Instruction* instr,
                                                      Program* program) {
    const std::string& mnemonic = instr->getMnemonicString();
    if (mnemonic != "subi" && mnemonic != "addi") return;

    auto regs = instr->getOperandRegisters(0);
    if (regs.empty()) return;

    Register* reg = regs[0];
    uint64_t val = context->getValue(reg, false);
    if (val == 0 && context->getValue(reg, true) == 0) return;

    int64_t lval = static_cast<int64_t>(val);
    AddressSpace* space = const_cast<AddressSpace*>(instr->getMinAddress().getAddressSpace());
    int64_t truncated = space->truncateOffset(lval);
    Address refAddr(space, truncated);

    if ((lval > 4096 || lval < 0) && program->getMemory()->getBlock(refAddr) != nullptr) {
        if (instr->getOperandReferences(2).empty()) {
            instr->addOperandReference(2, refAddr, &RefTypes::DATA, SourceType::ANALYSIS);
        }
    }
}

AddressSet PowerPCAddressAnalyzer::recoverSwitches(Program* program, SymbolicPropogator* symEval,
                                                     const AddressSetView& destinationSet,
                                                     TaskMonitor* monitor) {
    AddressSet results;
    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    if (!memory || !symTable || !listing) return results;

    AddressRangeIterator* iter = destinationSet.getAddressRanges(true);
    while (iter->hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        Instruction* jumpInstr = listing->getInstructionAt(addr);
        if (!jumpInstr) continue;

        // Get the register operand (typically r12 for PPC)
        auto regs = jumpInstr->getOperandRegisters(0);
        if (regs.empty()) continue;

        // Scan after the jump for table entries
        Address scanStart;
        try {
            scanStart = addr.add(jumpInstr->getLength());
        } catch (...) {
            continue;
        }

        // 4-byte entries are standard for PPC switch tables
        for (int i = 0; i < 64; ++i) {
            Address entryAddr;
            try {
                entryAddr = scanStart.add(i * 4);
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

            if (targetVal < 0x1000) break;

            Address targetAddr(addr.getAddressSpace(), static_cast<int64_t>(targetVal));
            if (!memory->getBlock(targetAddr)) break;

            std::string label = "ppc_switch_0x" + targetAddr.toString();
            symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
            results.add(targetAddr);
        }
    }
    return results;
}

void PowerPCAddressAnalyzer::createDataType(Program* program, Instruction* instr,
                                              const Address& address) {
    if (!program->getListing()->isUndefined(address)) return;

    const std::string& mnemonic = instr->getMnemonicString();
    if (mnemonic.empty() || (mnemonic[0] != 'l' && mnemonic[0] != 's')) return;

    // Determine size from mnemonic suffix
    DataType* dataType = &DWordDataType::dataType();
    if (mnemonic.size() >= 2) {
        char sizeChar = mnemonic[1];
        if (sizeChar == 'b') {
            dataType = &ByteDataType::dataType();
        } else if (sizeChar == 'h') {
            dataType = &WordDataType::dataType();
        }
    }

    Data* data = program->getListing()->createData(address, dataType);
    if (data) {
        (void)data;
    }
}

void PowerPCAddressAnalyzer::labelTable(Program* program, const Address& loc,
                                         const std::vector<Address>& targets) {
    SymbolTable* symTable = program->getSymbolTable();
    if (!symTable) return;

    std::string prefix = "jtbl_" + std::to_string(loc.getOffset());
    for (size_t i = 0; i < targets.size(); ++i) {
        if (!targets[i].isValid()) continue;
        std::string label = prefix + "_" + std::to_string(i);
        symTable->createLabel(targets[i], label, SourceType::ANALYSIS);
    }
}

bool PowerPCAddressAnalyzer::getDefaultPropagateR2Option(Program* program) {
    if (!program) return false;
    std::string format = program->getExecutableFormat();

    // r2 propagation is relevant for ELF 64-bit
    if (format.find("ELF") != std::string::npos) {
        const AddressSpace* space = program->getAddressFactory()->getDefaultAddressSpace();
        if (space && space->getSize() >= 64) {
            return true;
        }
    }

    return false;
}

bool PowerPCAddressAnalyzer::getDefaultPropagateR30Option(Program* program) {
    if (!program) return false;
    std::string format = program->getExecutableFormat();

    // r30 propagation is relevant for ELF 32-bit with __DT_PPC_GOT
    if (format.find("ELF") != std::string::npos) {
        const AddressSpace* space = program->getAddressFactory()->getDefaultAddressSpace();
        if (space && space->getSize() <= 32) {
            auto symbols = program->getSymbolTable()->getGlobalSymbols("__DT_PPC_GOT");
            if (!symbols.empty()) {
                return true;
            }
        }
    }

    return false;
}

void PowerPCAddressAnalyzer::registerOptions(Options& options, Program* program) {
    ConstantPropagationAnalyzer::registerOptions(options, program);
    options.registerBool("Restrict Address to same 256M page", checkHighNibbleOption, "");
    options.registerBool("Mark dual instruction references", markupDualInstructionOption,
                         "Turn on to mark all potential dual instruction refs");
    options.registerBool("Switch Table Recovery", recoverSwitchTables,
                         "Turn on to recover switch tables");
    options.registerBool("Propagate r2 register value",
                         getDefaultPropagateR2Option(program),
                         "Propagate r2 register value into called functions");
    options.registerBool("Propagate r30 register value",
                         getDefaultPropagateR30Option(program),
                         "Propagate r30 register value into called functions");
}

void PowerPCAddressAnalyzer::optionsChanged(Options& options, Program* program) {
    ConstantPropagationAnalyzer::optionsChanged(options, program);
    if (options.hasOption("Restrict Address to same 256M page"))
        checkHighNibbleOption = options.getBool("Restrict Address to same 256M page");
    if (options.hasOption("Mark dual instruction references"))
        markupDualInstructionOption = options.getBool("Mark dual instruction references");
    if (options.hasOption("Switch Table Recovery"))
        recoverSwitchTables = options.getBool("Switch Table Recovery");
    if (options.hasOption("Propagate r2 register value"))
        propagateR2value = options.getBool("Propagate r2 register value");
    if (options.hasOption("Propagate r30 register value"))
        propagateR30value = options.getBool("Propagate r30 register value");
}

} // namespace ghidra
