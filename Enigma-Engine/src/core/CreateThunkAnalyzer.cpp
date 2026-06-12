#include <ghidra/CreateThunkAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>

namespace ghidra {

CreateThunkAnalyzer::CreateThunkAnalyzer()
    : FunctionAnalyzer() {
    setPriority(AnalysisPriority::BLOCK_ANALYSIS.after().after());
    setDefaultEnablement(true);
    createOnlyThunks_ = true;
    analysisMessage_ = "Create Thunks : ";
}

bool CreateThunkAnalyzer::added(Program* program, const AddressSetView& set,
                                 TaskMonitor* monitor, MessageLog& log) {
    if (!createOnlyThunks_) {
        return true;
    }
    return FunctionAnalyzer::added(program, set, monitor, log);
}

void CreateThunkAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Create Thunks Early", createOnlyThunks_,
                          "If checked, create thunk functions early in analysis flow.");
}

void CreateThunkAnalyzer::optionsChanged(Options& options, Program* program) {
    createOnlyThunks_ = options.getBool("Create Thunks Early");
}

} // namespace ghidra
