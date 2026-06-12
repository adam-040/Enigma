#include <ghidra/SegmentedCallingConventionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/Memory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/PrototypeModel.h>
#include <cctype>
#include <algorithm>

namespace ghidra {

SegmentedCallingConventionAnalyzer::SegmentedCallingConventionAnalyzer()
    : AbstractAnalyzer("Segmented X86 Calling Conventions",
                       "Analyzes X86 programs with segmented address spaces to identify a calling convention for each function.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool SegmentedCallingConventionAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    Language* lang = program->getLanguage();
    return !lang->getSegmentedSpace().empty() && lang->supportsPcode();
}

bool SegmentedCallingConventionAnalyzer::added(Program* program, const AddressSetView& set,
                                                TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* memory = program->getMemory();
    auto* funcMgr = program->getFunctionManager();
    auto* compilerSpec = program->getCompilerSpec();
    if (!listing || !memory || !funcMgr || !compilerSpec) return false;

    auto instructions = listing->getInstructions(set);

    for (auto* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;
        if (!instr) continue;

        std::string mnemonic = instr->getMnemonicString();
        std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::tolower);

        if (mnemonic.size() < 3 || mnemonic.substr(0, 3) != "ret") continue;

        uint8_t byteVal = 0;
        try {
            byteVal = memory->getByte(instr->getMinAddress());
        } catch (const MemoryAccessException&) {
            continue;
        }

        const char* convention = nullptr;
        switch (byteVal) {
            case 0xca: convention = "__stdcall16far"; break;
            case 0xcb: convention = "__cdecl16far"; break;
            case 0xc3: convention = "__cdecl16near"; break;
            case 0xc2: convention = "__stdcall16near"; break;
        }

        if (!convention) continue;

        Function* func = funcMgr->getFunctionContaining(instr->getMinAddress());
        if (!func) continue;

        PrototypeModel* model = compilerSpec->getCallingConvention(convention);
        if (!model) {
            auto newModel = std::make_unique<PrototypeModel>(convention, convention);
            compilerSpec->addCallingConvention(convention, std::move(newModel));
            model = compilerSpec->getCallingConvention(convention);
        }
        if (model) {
            func->setCallingConvention(model);
        }
    }

    return true;
}

} // namespace ghidra
