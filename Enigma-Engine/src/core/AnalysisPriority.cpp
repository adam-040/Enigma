#include <ghidra/AnalysisPriority.h>

namespace ghidra {

const AnalysisPriority AnalysisPriority::FORMAT_ANALYSIS("FORMAT", 100);
const AnalysisPriority AnalysisPriority::BLOCK_ANALYSIS("BLOCK", 200);
const AnalysisPriority AnalysisPriority::DISASSEMBLY("DISASSEMBLY", 300);
const AnalysisPriority AnalysisPriority::CODE_ANALYSIS("CODE", 400);
const AnalysisPriority AnalysisPriority::FUNCTION_ANALYSIS("FUNCTION", 500);
const AnalysisPriority AnalysisPriority::REFERENCE_ANALYSIS("REFERENCE", 600);
const AnalysisPriority AnalysisPriority::DATA_ANALYSIS("DATA", 700);
const AnalysisPriority AnalysisPriority::FUNCTION_ID_ANALYSIS("FUNCTION ID", 800);
const AnalysisPriority AnalysisPriority::DATA_TYPE_PROPOGATION("DATA TYPE PROPOGATION", 900);
const AnalysisPriority AnalysisPriority::LOW_PRIORITY("LOW", 10000);
const AnalysisPriority AnalysisPriority::HIGHEST_PRIORITY("HIGH", 1);

AnalysisPriority::AnalysisPriority(int priority)
    : priority_(priority) {}

AnalysisPriority::AnalysisPriority(const std::string& name, int priority)
    : name_(name), priority_(priority) {}

AnalysisPriority AnalysisPriority::before() const {
    return AnalysisPriority(name_ + "-", priority_ - 1);
}

AnalysisPriority AnalysisPriority::after() const {
    return AnalysisPriority(name_ + "+", priority_ + 1);
}

AnalysisPriority AnalysisPriority::getInitial(const std::string& name) {
    return AnalysisPriority(name, 100);
}

AnalysisPriority AnalysisPriority::getNext(const std::string& nextName) const {
    return AnalysisPriority(nextName, priority_ + 100);
}

std::string AnalysisPriority::toString() const {
    std::string buf;
    if (!name_.empty()) {
        buf += "[" + name_ + "]  ";
    }
    buf += std::to_string(priority_);
    return buf;
}

} // namespace ghidra
