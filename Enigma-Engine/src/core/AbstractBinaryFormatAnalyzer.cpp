#include <ghidra/AbstractBinaryFormatAnalyzer.h>
#include <ghidra/Program.h>

namespace ghidra {

AbstractBinaryFormatAnalyzer::AbstractBinaryFormatAnalyzer(const std::string& name, const std::string& description)
    : AbstractAnalyzer(name, description, AnalyzerType::BYTE_ANALYZER) {
    // Priority: FORMAT_ANALYSIS
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool AbstractBinaryFormatAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    // Base class for format-specific analyzers (ELF, PE, Mach-O, PEF, COFF, COFF Archive).
    // Each subclass overrides added() with its own format detection logic.
    return true;
}

} // namespace ghidra
