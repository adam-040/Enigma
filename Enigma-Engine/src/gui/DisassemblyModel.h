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

    int totalInstructions() const { return totalInstructions_; }
    uint64_t rowToAddress(int row) const;
    int addressToRow(uint64_t addr) const;

private:
    struct InstructionEntry {
        uint64_t address = 0;
        int blockIndex = -1;
    };

    std::vector<InstructionEntry> instructions_;
    std::vector<MemoryBlockInfo> blocks_;
    std::unordered_map<uint64_t, int> addressToRow_;
    int totalInstructions_ = 0;
};
