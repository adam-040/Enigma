#include <ghidra/RttiAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ghidra {

static constexpr uint32_t COLON_COLON_SIG = 0xFFFFFFFF;

static uint32_t read32(const uint8_t* buf) {
    return (static_cast<uint32_t>(buf[0]) << 0) |
           (static_cast<uint32_t>(buf[1]) << 8) |
           (static_cast<uint32_t>(buf[2]) << 16) |
           (static_cast<uint32_t>(buf[3]) << 24);
}

RttiAnalyzer::RttiAnalyzer()
    : AbstractAnalyzer("Windows x86 PE RTTI Analyzer",
                       "Finds and creates RTTI metadata structures and associated vf tables.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.before());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool RttiAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable";
}

bool RttiAnalyzer::added(Program* program, const AddressSetView& set,
                          TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    if (!memory || !symTable) return true;

    if (monitor) monitor->setMessage("Analyzing MSVC RTTI structures...");

    MemoryBlock* rdataBlock = memory->getBlock(".rdata");
    if (!rdataBlock) {
        rdataBlock = memory->getBlock(".text");
    }
    if (!rdataBlock) return true;

    Address blockStart = rdataBlock->getStart();
    Address blockEnd = rdataBlock->getEnd();
    int64_t blockSize = blockEnd.getOffset() - blockStart.getOffset() + 1;
    if (blockSize <= 0) return true;

    std::vector<uint8_t> blockData(static_cast<size_t>(blockSize));
    if (memory->getBytes(blockStart, blockData.data(), static_cast<int>(blockSize))
        != static_cast<int>(blockSize)) {
        return true;
    }

    if (monitor) {
        monitor->initialize(static_cast<int>(blockSize));
    }

    int rttiCount = 0;

    for (int i = 0; i + 12 <= static_cast<int>(blockSize); ++i) {
        if (monitor && monitor->isCancelled()) break;

        if (i % 4 != 0) continue;
        if (monitor && i % 4096 == 0) monitor->setProgress(i);

        uint32_t sig = read32(&blockData[i]);

        if (sig == 0x3F5F5F52) {
            size_t maxNameLen = std::min(static_cast<size_t>(blockSize - i - 4),
                                          static_cast<size_t>(256));
            int nameLen = 0;
            for (size_t j = 0; j < maxNameLen; ++j) {
                if (blockData[i + 4 + j] == 0) {
                    nameLen = static_cast<int>(j);
                    break;
                }
            }
            if (nameLen < 2) continue;

            std::string rttiName(reinterpret_cast<const char*>(&blockData[i]), nameLen);
            if (rttiName.find("??_R") != 0) continue;

            // Found "??_R..." name string. Scan backward for a pointer to it.
            for (int j = i - 4; j >= 0 && j > i - 4096; j -= 4) {
                uint32_t ptrToName = read32(&blockData[j]);
                Address nameAddr = blockStart.add(static_cast<int64_t>(i));

                // Check if this DWORD at offset j points to our name
                Address pointedAddr = blockStart.add(static_cast<int64_t>(ptrToName));
                if (pointedAddr == nameAddr && j >= 8) {
                    Address tiAddr = blockStart.add(static_cast<int64_t>(j - 4));
                    uint32_t vtablePtr = read32(&blockData[j - 4]);
                    Address vtableAddr = blockStart.add(static_cast<int64_t>(vtablePtr));

                    if (vtableAddr >= blockStart && vtableAddr <= blockEnd) {
                        std::string labelName = "RTTI_TypeDescriptor_" + rttiName;
                        symTable->createLabel(tiAddr, labelName, SourceType::ANALYSIS);

                        std::string nameLabel = "RTTI_Name_" + rttiName;
                        symTable->createLabel(nameAddr, nameLabel, SourceType::ANALYSIS);

                        ++rttiCount;
                    }
                    break;
                }
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(rttiCount) +
                            " RTTI type descriptors");
    }

    if (rttiCount == 0) {
        Msg::info(getName(), "No MSVC RTTI structures found in .rdata/.text");
    }

    return true;
}

} // namespace ghidra
