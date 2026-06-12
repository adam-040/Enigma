#include <ghidra/HCS12ConventionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/RefType.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Register.h>
#include <ghidra/RegisterValue.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/SourceType.h>
#include <ghidra/PrototypeModel.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <algorithm>
#include <cctype>

namespace ghidra {

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

HCS12ConventionAnalyzer::HCS12ConventionAnalyzer()
    : AbstractAnalyzer("HCS12 Calling Convention",
                       "Analyzes HCS12 programs with paged memory access to identify "
                       "a calling convention for each function.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS);
}

bool HCS12ConventionAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    Processor processor = program->getLanguage()->getProcessor();
    return processor == Processor("HCS-12") || processor == Processor("HCS-12X");
}

void HCS12ConventionAnalyzer::checkReturn(Program* program, Instruction* instr) {
    if (!instr || !instr->getFlowType() || !instr->getFlowType()->isTerminal()) {
        return;
    }

    std::string mnemonic = toLower(instr->getMnemonicString());

    Register* xgate = program->getRegister("XGATE");
    if (xgate) {
        RegisterValue* xgateValue = program->getProgramContext()->getRegisterValue(
            xgate, instr->getAddress());
        if (xgateValue && !xgateValue->getValue().empty() &&
            xgateValue->getUnsignedOffset() == 1) {
            setPrototypeModel(program, instr, "__asm_xgate");
            return;
        }
    }

    if (mnemonic == "rtc") {
        setPrototypeModel(program, instr, "__asmA_longcall");
        return;
    }

    if (mnemonic == "rts") {
        setPrototypeModel(program, instr, "__asmA");
        return;
    }
}

void HCS12ConventionAnalyzer::setPrototypeModel(Program* program, Instruction* instr,
                                                  const std::string& convention) {
    Function* func = program->getFunctionManager()->getFunctionContaining(
        instr->getAddress());
    if (!func) return;

    if (func->getSource() != SourceType::DEFAULT) return;

    PrototypeModel* model = program->getFunctionManager()->getCallingConvention(convention);
    if (model) {
        func->setCallingConvention(model);
    }
}

bool HCS12ConventionAnalyzer::added(Program* program, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    FunctionIterator funcIter = program->getFunctionManager()->getFunctions(set, true);
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        Function* function = funcIter.next();
        if (!function) continue;

        const AddressSet& body = function->getBody();
        std::vector<Instruction*> instructions = program->getListing()->getInstructions(body);
        for (Instruction* instr : instructions) {
            if (!instr) continue;

            if (instr->getFlowType() && instr->getFlowType()->isTerminal()) {
                checkReturn(program, instr);
            }
        }
    }

    return true;
}

} // namespace ghidra
