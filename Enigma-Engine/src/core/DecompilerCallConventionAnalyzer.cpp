#include <ghidra/DecompilerCallConventionAnalyzer.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/DecompilerAdapter.h>
#include <ghidra/Msg.h>

namespace ghidra {

DecompilerCallConventionAnalyzer::DecompilerCallConventionAnalyzer()
    : AbstractAnalyzer("Decompiler Call Convention",
                       "Uses the decompiler to deduce function parameters and calling conventions.",
                       AnalyzerType::FUNCTION_SIGNATURES_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool DecompilerCallConventionAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr && program->getLanguage() != nullptr && program->getLanguage()->supportsPcode();
}

bool DecompilerCallConventionAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    if (!funcMgr) return false;

    // Create the C++ Decompiler Adapter
    auto adapter = createDecompilerAdapter();
    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!adapter || !programDB || !adapter->initialize(programDB)) {
        log.append("DecompilerCallConventionAnalyzer: Failed to initialize decompiler adapter.");
        return false;
    }

    auto iter = funcMgr->getFunctions(true);
    while (iter.hasNext()) {
        auto* func = iter.next();
        if (monitor && monitor->isCancelled()) break;

        // Ensure the function doesn't already have a hardcoded calling convention
        if (func->getCallingConvention() != nullptr) {
            continue;
        }

        auto decompRes = adapter->decompileFunction(func, 10);
        if (decompRes.success) {
            PrototypeModel* defaultConv = funcMgr->getDefaultCallingConvention();
            if (defaultConv) {
                func->setCallingConvention(defaultConv);
            }
        }
    }

    return true;
}

} // namespace ghidra
