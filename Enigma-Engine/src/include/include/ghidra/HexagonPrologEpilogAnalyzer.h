#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <cstdint>

namespace ghidra {

class HexagonPrologEpilogAnalyzer : public AbstractAnalyzer {
public:
    enum class FixupType { NameOnly, Inline, CallFixup };

    HexagonPrologEpilogAnalyzer();
    ~HexagonPrologEpilogAnalyzer() override = default;

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

private:
    bool isProlog(Program* program, Address entryPoint, bool recurseOk, TaskMonitor* monitor);
    bool isEpilog(Program* program, Address entryPoint, bool recurseOk, TaskMonitor* monitor);
    bool hasContinuationFunction(Program* program, Address jumpFromAddr, bool checkProlog, TaskMonitor* monitor);
    bool setPrologEpilog(Program* program, Address entryPoint, bool isProlog, TaskMonitor* monitor);
    void setPrologEpilog(Function* function, bool isProlog);

    struct InstructionMaskValue {
        uint32_t mask;
        uint32_t value;

        InstructionMaskValue(uint32_t m, uint32_t v) : mask(m), value(v) {}

        bool isMatch(const uint8_t* bytes) const;
    };

    static const char* CALL_FIXUP_PROLOG_NAME;
    static const char* CALL_FIXUP_EPILOG_NAME;

    InstructionMaskValue NOP;
    InstructionMaskValue JUMPR_LR;
    InstructionMaskValue JUMP;
    InstructionMaskValue MEMD_PUSH;
    InstructionMaskValue MEMD_POP;
    InstructionMaskValue DEALLOCFRAME;
    InstructionMaskValue DEALLOC_RETURN;

    FixupType fixupType_{FixupType::CallFixup};
};

} // namespace ghidra
