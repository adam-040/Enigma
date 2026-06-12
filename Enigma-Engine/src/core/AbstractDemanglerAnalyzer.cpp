#include <ghidra/AbstractDemanglerAnalyzer.h>
#include <ghidra/Program.h>

namespace ghidra {

AbstractDemanglerAnalyzer::AbstractDemanglerAnalyzer(const std::string& name, const std::string& description)
    : AbstractAnalyzer(name, description, AnalyzerType::BYTE_ANALYZER) {
    // Priority: DATA_TYPE_PROPOGATION.before().before().before().before()
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.before().before().before().before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool AbstractDemanglerAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    // Base class for Demanglers (GNU, MSVC, Rust, Swift).
    // Each subclass overrides added() with its own demangling logic.
    return true;
}

} // namespace ghidra
