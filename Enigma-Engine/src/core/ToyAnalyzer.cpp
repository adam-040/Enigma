#include <ghidra/ToyAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/AnalysisPriority.h>

namespace ghidra {

ToyAnalyzer::ToyAnalyzer()
    : ConstantPropagationAnalyzer(PROCESSOR_NAME) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS.after());
}

bool ToyAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == PROCESSOR_NAME;
}

AddressSet ToyAnalyzer::flowConstants(Program* program, const Address& flowStart,
                                       const AddressSetView* flowSet,
                                       SymbolicPropogator* symEval,
                                       TaskMonitor* monitor) {
    return ConstantPropagationAnalyzer::flowConstants(program, flowStart, flowSet, symEval, monitor);
}

} // namespace ghidra
