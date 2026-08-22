#pragma once

#include <ghidra/AbstractAnalyzer.h>
#include <ghidra/Address.h>
#include <vector>
#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <queue>

namespace ghidra {

class ProgramDB;
struct DisassembledInstruction;
class Disassembler;

class DisassemblyAnalyzer : public AbstractAnalyzer {
public:
    DisassemblyAnalyzer();
    bool added(Program* program, const AddressSetView& set,
               TaskMonitor* monitor, MessageLog& log) override;
    bool canAnalyze(Program* program) const override;

private:
    // MIPS16e / microMIPS context tracking (GP-6766)
    // contextTable_ maps address -> ISA mode (0=MIPS32, 1=MIPS16e)
    std::unordered_map<uint64_t, int> contextTable_;
    int currentIsaMode_ = 0;
    bool isMips_ = false;

    bool isMips16eSwitchInstruction(const std::string& mnemonic) const;
    void handleMips16eContextSwitch(const DisassembledInstruction& di,
                                    Disassembler* disassembler, uint64_t addr);
};

} // namespace ghidra
