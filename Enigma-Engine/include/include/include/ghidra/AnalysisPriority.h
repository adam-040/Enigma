#pragma once

#include <string>

namespace ghidra {

class AnalysisPriority {
public:
    static const AnalysisPriority FORMAT_ANALYSIS;
    static const AnalysisPriority BLOCK_ANALYSIS;
    static const AnalysisPriority DISASSEMBLY;
    static const AnalysisPriority CODE_ANALYSIS;
    static const AnalysisPriority FUNCTION_ANALYSIS;
    static const AnalysisPriority REFERENCE_ANALYSIS;
    static const AnalysisPriority DATA_ANALYSIS;
    static const AnalysisPriority FUNCTION_ID_ANALYSIS;
    static const AnalysisPriority DATA_TYPE_PROPOGATION;
    static const AnalysisPriority LOW_PRIORITY;
    static const AnalysisPriority HIGHEST_PRIORITY;

    AnalysisPriority(int priority);
    AnalysisPriority(const std::string& name, int priority);

    int priority() const { return priority_; }
    const std::string& getName() const { return name_; }

    AnalysisPriority before() const;
    AnalysisPriority after() const;

    std::string toString() const;

private:
    std::string name_;
    int priority_;

    static AnalysisPriority getInitial(const std::string& name);
    AnalysisPriority getNext(const std::string& nextName) const;
};

} // namespace ghidra
