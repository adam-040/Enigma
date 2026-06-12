#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class Pic16Analyzer : public ConstantPropagationAnalyzer {
public:
    Pic16Analyzer();
    ~Pic16Analyzer() override = default;
};

} // namespace ghidra
