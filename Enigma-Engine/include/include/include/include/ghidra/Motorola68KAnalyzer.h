#pragma once

#include <ghidra/ConstantPropagationAnalyzer.h>

namespace ghidra {

class Motorola68KAnalyzer : public ConstantPropagationAnalyzer {
public:
    Motorola68KAnalyzer();
    ~Motorola68KAnalyzer() override = default;
};

} // namespace ghidra
