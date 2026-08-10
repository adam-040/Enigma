#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <QString>

namespace ghidra {
class ProgramDB;
class DecompInterface;
class MemoryBlock;
}

// One rendered row in the disassembly view.
struct DisasmRow {
    enum class Kind {
        Instruction,    // a decoded instruction at `address`
        FunctionHeader, // "; === name ==="
        GapComment      // "; --- N bytes of data ---"
    };
    Kind kind = Kind::Instruction;
    uint64_t address = 0; // instruction address (Instruction) or anchor (header/gap)
    int length = 0;       // instruction byte length (Instruction)
    QString text;         // header name or gap comment text
};

class DisassemblyModel {
public:
    struct MemoryBlockInfo {
        uint64_t start = 0;
        uint64_t size = 0;
        int firstRow = -1;
        int instrCount = 0;
        bool executable = false;
    };

    void buildIndex(ghidra::ProgramDB* program, ghidra::DecompInterface* decomp);
    void clear();

    int rowCount() const { return static_cast<int>(rows_.size()); }
    int totalInstructions() const { return instrCount_; }

    const DisasmRow* rowAt(int row) const;
    uint64_t rowToAddress(int row) const;
    int addressToRow(uint64_t addr) const;

    int instructionLengthAt(uint64_t addr) const;

private:
    struct FuncInfo {
        uint64_t entry = 0;
        uint64_t bodyStart = 0;
        uint64_t bodyEnd = 0;
        QString name;
    };

    std::vector<DisasmRow> rows_;
    std::unordered_map<uint64_t, int> addressToRow_;
    std::unordered_map<uint64_t, int> lengthByAddress_;
    std::vector<MemoryBlockInfo> blocks_;
    int instrCount_ = 0;

    void buildFromFunctions(ghidra::ProgramDB* program, ghidra::DecompInterface* decomp,
                            const std::vector<FuncInfo>& functions);
    void buildGapComments(ghidra::ProgramDB* program,
                          const std::vector<std::pair<uint64_t, uint64_t>>& coveredRanges);
    QString analyzeGap(ghidra::ProgramDB* program, uint64_t gapStart, uint64_t gapEnd) const;
};
