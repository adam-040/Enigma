// NOTE: This is a standalone wrapper used only by test_compile.cpp and
// enigma_decompile.cpp (native pipeline). The main decompilation tool
// (enigma_decompile_full.cpp) uses the decompiler library's own Sleigh
// via SleighArchitecture (decompiler/sleigh_arch.hh).

#pragma once

#include <ghidra/Translate.h>
#include <ghidra/ContextDatabase.h>
#include <ghidra/PcodeInject.h>
#include <ghidra/PcodeCapstoneMapper.h>
#include <string>
#include <vector>
#include <map>
#include <cstddef>

namespace ghidra {

class SleighLoadImage;
struct DisassembledInstruction;

class Sleigh : public Translate {
private:
    ContextDatabase contextDatabase;
    PcodeInjectLibrary injectLibrary;
    std::string slaFile;
    bool initialized;
    int4 maxInstructionBytes;
    size_t capstoneHandle_;
    PcodeCapstoneMapper mapper_;
    bool capstoneInitialized_;
    std::string archName_;
    int archBitness_;

    struct ContextCache {
        Address lastAddr;
        std::map<std::string, uintb> values;
    };
    ContextCache cache;

    bool decodeInstruction(const Address& addr, DisassembledInstruction& di) const;

public:
    Sleigh(LoadImage* ld, const std::string& slaPath);
    ~Sleigh() override;

    bool initialize();
    bool isInitialized() const { return initialized; }

    int4 instructionLength(const Address& addr) const override;
    int4 printAssembly(const Address& addr, std::string& output) const override;
    int4 oneInstruction(Funcdata& fd, const Address& addr) override;

    void setContextDefault(const std::string& name, uintb value) override;
    void allowContextSet(bool val) override;

    ContextDatabase& getContextDatabase() { return contextDatabase; }
    const ContextDatabase& getContextDatabase() const { return contextDatabase; }
    PcodeInjectLibrary& getInjectLibrary() { return injectLibrary; }
    const PcodeInjectLibrary& getInjectLibrary() const { return injectLibrary; }

    bool hasFallthrough(const Address& addr) const override;
    Address getFallthrough(const Address& addr) const override;
    bool isBranchFallthrough(const Address& addr) const override;
    bool isCallInstruction(const Address& addr) const override;
    bool isReturnInstruction(const Address& addr) const override;

    const std::string& getSlaFile() const { return slaFile; }
    int4 getMaxInstructionBytes() const { return maxInstructionBytes; }

    void setArchitecture(const std::string& arch, int bitness);
    PcodeCapstoneMapper& getMapper() { return mapper_; }
};

} // namespace ghidra
