#include <ghidra/Analyzer.h>

namespace ghidra {

std::string analyzerTypeName(AnalyzerType type) {
    switch (type) {
        case AnalyzerType::BYTE_ANALYZER: return "Byte Analyzer";
        case AnalyzerType::INSTRUCTION_ANALYZER: return "Instructions Analyzer";
        case AnalyzerType::FUNCTION_ANALYZER: return "Function Analyzer";
        case AnalyzerType::FUNCTION_MODIFIERS_ANALYZER: return "Function-modifiers Analyzer";
        case AnalyzerType::FUNCTION_SIGNATURES_ANALYZER: return "Function-Signatures Analyzer";
        case AnalyzerType::DATA_ANALYZER: return "Data Analyzer";
    }
    return "Unknown";
}

std::string analyzerTypeDescription(AnalyzerType type) {
    switch (type) {
        case AnalyzerType::BYTE_ANALYZER: return "Triggered when bytes are added (memory block added).";
        case AnalyzerType::INSTRUCTION_ANALYZER: return "Triggered when instructions are created.";
        case AnalyzerType::FUNCTION_ANALYZER: return "Triggered when functions are created.";
        case AnalyzerType::FUNCTION_MODIFIERS_ANALYZER: return "Triggered when a function's modifier changes";
        case AnalyzerType::FUNCTION_SIGNATURES_ANALYZER: return "Triggered when a function's signature changes.";
        case AnalyzerType::DATA_ANALYZER: return "Triggered when data is created.";
    }
    return "";
}

} // namespace ghidra
