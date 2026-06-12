#include <ghidra/CallFixupChangeAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

CallFixupChangeAnalyzer::CallFixupChangeAnalyzer()
    : CallFixupAnalyzer("Call-Fixup Installer", AnalyzerType::FUNCTION_MODIFIERS_ANALYZER, false) {
}

bool CallFixupChangeAnalyzer::added(Program* program, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    return CallFixupAnalyzer::added(program, set, monitor, log);
}

} // namespace ghidra
