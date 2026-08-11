#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/ConstantPropagationContextEvaluator.h>
#include <ghidra/SymbolicPropogator.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/Varnode.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefTypeFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>

namespace ghidra {

ConstantPropagationAnalyzer::ConstantPropagationAnalyzer()
    : AbstractAnalyzer("Constant Propagation",
                       "Create references from propagated constant values in p-code.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.before().before());
}

ConstantPropagationAnalyzer::ConstantPropagationAnalyzer(const std::string& processorName)
    : AbstractAnalyzer("Constant Propagation (" + processorName + ")",
                       "Create references from propagated constant values in " + processorName + " p-code.",
                       AnalyzerType::INSTRUCTION_ANALYZER),
      processorName_(processorName) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.before().before());
}

bool ConstantPropagationAnalyzer::canAnalyze(Program* program) const {
    if (processorName_.empty()) return true;
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == processorName_;
}

bool ConstantPropagationAnalyzer::getDefaultEnablement(Program* program) const {
    Address min = program->getMinAddress();
    if (!min.isValid() || min.getOffset() == 0) return false;
    if (program->getAddressFactory()->getDefaultAddressSpace()->getSize() < 32) return false;
    return true;
}

bool ConstantPropagationAnalyzer::added(Program* program, const AddressSetView& set,
                                          TaskMonitor* monitor, MessageLog& log) {
    int count = 0;
    if (monitor) {
        monitor->initialize(set.getNumAddresses());
    }

    Listing* listing = program->getListing();
    Memory* memory = program->getMemory();

    auto instructions = listing->getInstructions(set);
    for (Instruction* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) {
            monitor->setProgress(++count);
        }
        checkInstruction(program, instr, memory);
    }

    // Symbolic constant propagation through each function body.
    // This is what creates references for LEA/mov-address patterns
    // (e.g. x86 "lea reg, [rip+disp]" -> string/data address reference).
    // NOTE: recursion inside SymbolicPropogator is depth-limited
    // (MAX_FLOW_CALL_DEPTH) to prevent stack overflow on call cycles;
    // C++ try/catch cannot catch the resulting AccessViolation.
    SymbolicPropogator symEval(program);
    auto funcIter = program->getFunctionManager()->getFunctions(set, true);
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        Function* func = funcIter.next();
        if (!func) continue;
        try {
            flowConstants(program, func->getEntryPoint(), &func->getBody(), &symEval, monitor);
        } catch (const std::exception&) {
            // Propagation is best-effort; a failure on one function must not
            // abort the whole analysis pass.
        } catch (...) {
        }
    }
    return true;
}

void ConstantPropagationAnalyzer::checkInstruction(Program* program, Instruction* instr,
                                                     Memory* memory) {
    const auto& pcode = instr->getPcode();
    for (PcodeOp* op : pcode) {
        int opcode = op->getOpcode();
        if (opcode == PcodeOp::COPY) {
            handleCopyConstant(program, instr, op);
        } else if (opcode == PcodeOp::INT_ADD || opcode == PcodeOp::INT_SUB) {
            handleAddConstant(program, instr, op);
        }
    }
}

void ConstantPropagationAnalyzer::handleCopyConstant(Program* program, Instruction* instr,
                                                       PcodeOp* op) {
    if (op->getNumInputs() < 1) return;
    Varnode* input = op->getInput(0);
    if (!input || !input->isConstant()) return;

    AddressSpace* space = const_cast<AddressSpace*>(instr->getAddress().getAddressSpace());
    Address addr(space, input->getOffset());
    if (!isValidAddress(program, program->getMemory(), addr)) return;

    if (!instr->getOperandReferences(0).empty()) return;

    const RefType* refType = RefTypeFactory::getDefaultMemoryRefType(instr, 0, addr, false);
    instr->addOperandReference(0, addr, refType, SourceType::ANALYSIS);
}

void ConstantPropagationAnalyzer::handleAddConstant(Program* program, Instruction* instr,
                                                      PcodeOp* op) {
    if (op->getNumInputs() < 2) return;

    Varnode* in0 = op->getInput(0);
    Varnode* in1 = op->getInput(1);
    if (!in0 || !in1) return;

    // Need at least one constant input
    Varnode* constVn = in0->isConstant() ? in0 : (in1->isConstant() ? in1 : nullptr);
    if (!constVn) return;

    // Get the constant value
    uint64_t constVal = constVn->getOffset();

    // If the constant alone is a valid address, use it
    AddressSpace* space = const_cast<AddressSpace*>(instr->getAddress().getAddressSpace());
    Address addr(space, static_cast<int64_t>(constVal));
    if (!isValidAddress(program, program->getMemory(), addr)) return;

    if (!instr->getOperandReferences(0).empty()) return;

    const RefType* refType = RefTypeFactory::getDefaultMemoryRefType(instr, 0, addr, false);
    instr->addOperandReference(0, addr, refType, SourceType::ANALYSIS);
}

bool ConstantPropagationAnalyzer::isValidAddress(Program* program, Memory* memory,
                                                   const Address& addr) {
    if (!addr.isValid()) return false;

    // Check if it's in an initialized memory block
    MemoryBlock* block = memory->getBlock(addr);
    if (block != nullptr && block->isInitialized()) return true;

    // Check if there's a symbol at that address
    Symbol* sym = program->getSymbolTable()->getPrimarySymbol(addr);
    if (sym != nullptr && sym->getSource() != SourceType::DEFAULT) return true;

    return false;
}

void ConstantPropagationAnalyzer::registerOptions(Options& options, Program* program) {
    AbstractAnalyzer::registerOptions(options, program);
}

void ConstantPropagationAnalyzer::optionsChanged(Options& options, Program* program) {
    AbstractAnalyzer::optionsChanged(options, program);
}

AddressSet ConstantPropagationAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                                       const AddressSetView* flowSet,
                                                       SymbolicPropogator* symEval,
                                                       TaskMonitor* monitor) {
    ConstantPropagationContextEvaluator eval(monitor, trustWriteMemOption,
                                             minStoreLoadRefAddress,
                                             minSpeculativeRefAddress,
                                             maxSpeculativeRefAddress);
    eval.setTrustWritableMemory(trustWriteMemOption);
    eval.setMinSpeculativeOffset(minSpeculativeRefAddress);
    eval.setMaxSpeculativeOffset(maxSpeculativeRefAddress);
    eval.setMinStoreLoadOffset(minStoreLoadRefAddress);
    eval.setCreateComplexDataFromPointers(createComplexDataFromPointers);

    return symEval->flowConstants(flowStart, flowSet, &eval, true, monitor);
}

} // namespace ghidra
