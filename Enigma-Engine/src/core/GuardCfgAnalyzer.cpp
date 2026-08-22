#include <ghidra/GuardCfgAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Msg.h>
#include <ghidra/Language.h>
#include <ghidra/Address.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

namespace ghidra {

namespace {

// Guard CF flag constants
static const uint32_t IMAGE_GUARD_CF_INSTRUMENTED                    = 0x00000100;
static const uint32_t IMAGE_GUARD_CF_WRITE_EXPORT_SUPPRESSED         = 0x00000200;
static const uint32_t IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          = 0x00000400;
static const uint32_t IMAGE_GUARD_RF_INSTRUMENTED                    = 0x00010000;
static const uint32_t IMAGE_GUARD_RF_FUNCTION_TABLE_PRESENT          = 0x00040000;
static const uint32_t IMAGE_GUARD_RF_VERIFY_FUNCTIONTABLE_POINTER    = 0x00080000;

// PE data directory index for Load Config
static const int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;

static uint16_t readU16LE(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

static uint32_t readU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t readU64LE(const uint8_t* p) {
    return static_cast<uint64_t>(p[0]) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

// Read a 32-bit relative virtual address and convert to absolute address
static Address rvaToAddr(Memory* memory, uint32_t rva, AddressSpace* space) {
    if (rva == 0) return Address();
    return Address(space, static_cast<int64_t>(rva));
}

// Get a string representation of Guard CF flags
static std::string guardFlagsToString(uint32_t flags) {
    std::string result;
    if (flags & IMAGE_GUARD_CF_INSTRUMENTED)                result += "CF_INSTRUMENTED|";
    if (flags & IMAGE_GUARD_CF_WRITE_EXPORT_SUPPRESSED)     result += "CF_WRITE_EXPORT_SUPPRESSED|";
    if (flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT)      result += "CF_FUNCTION_TABLE_PRESENT|";
    if (flags & IMAGE_GUARD_RF_INSTRUMENTED)                result += "RF_INSTRUMENTED|";
    if (flags & IMAGE_GUARD_RF_FUNCTION_TABLE_PRESENT)      result += "RF_FUNCTION_TABLE_PRESENT|";
    if (flags & IMAGE_GUARD_RF_VERIFY_FUNCTIONTABLE_POINTER) result += "RF_VERIFY_FT_PTR|";
    if (!result.empty() && result.back() == '|') result.pop_back();
    if (result.empty()) result = "NONE";
    return result;
}

} // anonymous namespace

GuardCfgAnalyzer::GuardCfgAnalyzer()
    : AbstractAnalyzer("Guard CFG Analyzer",
                       "Parses PE Load Config directory for Guard CFG and DVRT metadata.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool GuardCfgAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    try {
        const std::string& format = program->getExecutableFormat();
        std::string lower = format;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower.find("pe") != std::string::npos ||
               lower.find("pe32") != std::string::npos ||
               lower.find("pecoff") != std::string::npos;
    } catch (...) {
        return false;
    }
}

bool GuardCfgAnalyzer::added(Program* program, const AddressSetView& set,
                              TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    try {
    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    if (!memory || !symTable || !listing) return true;

    std::cerr << "[GuardCfgAnalyzer] Running on " << program->getName() << std::endl;
    int blocksScanned = 0;
    int peFound = 0;

    AddressSpace* defaultSpace = nullptr;
    if (program->getLanguage()) {
        defaultSpace = program->getLanguage()->getDefaultSpace();
    }
    if (!defaultSpace) return true;

    bool is64 = (defaultSpace->getSize() == 64);
    int ptrSize = is64 ? 8 : 4;

    // Scan ALL non-external memory blocks for PE headers
    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;
        if (block->isExternalBlock()) continue;

        Address blockStart = block->getStart();
        uint64_t blockSize = block->getSize();
        if (blockSize < 0x40) continue;

        std::vector<uint8_t> headerData(static_cast<size_t>(std::min(static_cast<uint64_t>(0x200), blockSize)));
        if (memory->getBytes(blockStart, headerData.data(), static_cast<int>(headerData.size()))
            != static_cast<int>(headerData.size())) continue;

        blocksScanned++;

        // Find "PE\0\0" signature
        int peOffset = -1;
        for (size_t i = 0; i + 4 <= headerData.size(); ++i) {
            if (headerData[i] == 'P' && headerData[i+1] == 'E' &&
                headerData[i+2] == 0 && headerData[i+3] == 0) {
                peOffset = static_cast<int>(i);
                break;
            }
        }
        if (peOffset < 0) continue;

        peFound++;
        std::cerr << "[GuardCfgAnalyzer] PE signature found in block '" << block->getName()
                  << "' at offset " << peOffset << std::endl;

        // Read COFF header (20 bytes after PE signature)
        int coffOff = peOffset + 4;
        if (coffOff + 20 > static_cast<int>(headerData.size())) continue;
        uint16_t machine = readU16LE(&headerData[coffOff]);
        uint16_t numSections = readU16LE(&headerData[coffOff + 2]);
        uint32_t optHeaderSize = readU16LE(&headerData[coffOff + 16]);

        // Check if PE32 or PE32+
        int optOff = coffOff + 20;
        if (optOff + static_cast<int>(optHeaderSize) > static_cast<int>(headerData.size())) continue;
        uint16_t optMagic = readU16LE(&headerData[optOff]);
        bool pe32plus = (optMagic == 0x20B);

        // Get ImageBase
        uint64_t imageBase;
        if (pe32plus) {
            imageBase = readU64LE(&headerData[optOff + 24]);
        } else {
            imageBase = static_cast<uint64_t>(readU32LE(&headerData[optOff + 28]));
        }

        // DllCharacteristics is at different offsets
        // PE32: optOff+46 (16-bit), PE32+: optOff+70 (16-bit)
        int dllCharOff = pe32plus ? (optOff + 70) : (optOff + 46);
        if (dllCharOff + 2 > static_cast<int>(headerData.size())) continue;
        uint16_t dllCharacteristics = readU16LE(&headerData[dllCharOff]);

        // Check Guard CF flag (bit 12)
        bool guardCfgEnabled = (dllCharacteristics & 0x0400) != 0;

        // Read data directory entries
        // Data directories start after standard fields
        // PE32: optOff+96, PE32+: optOff+112
        int dataDirOff = pe32plus ? (optOff + 112) : (optOff + 96);
        int numDataDirs;
        if (pe32plus) {
            numDataDirs = static_cast<int>(readU32LE(&headerData[optOff + 108]));
        } else {
            numDataDirs = static_cast<int>(readU32LE(&headerData[optOff + 92]));
        }

        if (numDataDirs <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) continue;
        if (dataDirOff + (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG + 1) * 8 > static_cast<int>(headerData.size())) continue;

        // Read Load Config directory RVA and Size
        int loadConfigDirOff = dataDirOff + IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * 8;
        uint32_t loadConfigRVA = readU32LE(&headerData[loadConfigDirOff]);
        uint32_t loadConfigSize = readU32LE(&headerData[loadConfigDirOff + 4]);

        if (loadConfigRVA == 0 || loadConfigSize < 4) continue;
        if (loadConfigSize > 0x1000) loadConfigSize = 0x1000; // sanity cap

        // Read the Load Config directory from memory at imageBase + loadConfigRVA
        Address loadConfigAddr(defaultSpace, static_cast<int64_t>(imageBase + loadConfigRVA));
        if (!memory->getBlock(loadConfigAddr)) {
            // Try using RVA directly
            loadConfigAddr = Address(defaultSpace, static_cast<int64_t>(loadConfigRVA));
            if (!memory->getBlock(loadConfigAddr)) continue;
        }

        std::vector<uint8_t> lcData(static_cast<size_t>(loadConfigSize));
        if (memory->getBytes(loadConfigAddr, lcData.data(), static_cast<int>(loadConfigSize))
            != static_cast<int>(loadConfigSize)) continue;

        // Parse IMAGE_LOAD_CONFIG_DIRECTORY
        // Size field is at offset 0
        uint32_t structSize = readU32LE(&lcData[0]);
        if (structSize < 4) continue;

        // Guard CF flags are at different offsets depending on PE32/PE32+ and version
        // For PE32+ (version >= 22 for newer features):
        //   GuardCFFlags: offset 108 (for IMAGE_LOAD_CONFIG_DIRECTORY64)
        // For PE32:
        //   GuardCFFlags: offset 92 (for IMAGE_LOAD_CONFIG_DIRECTORY32)
        // But these are relative to the start of the Load Config directory

        uint32_t guardFlags = 0;
        uint64_t guardCFFunctionTable = 0;
        uint32_t guardCFFunctionCount = 0;
        uint64_t guardCFCheckFunctionPointer = 0;
        uint64_t guardCFDispatchFunctionPointer = 0;
        uint64_t guardRFFunctionTable = 0;
        uint32_t guardRFFunctionCount = 0;

        if (pe32plus) {
            // PE32+ Load Config Directory layout
            if (structSize >= 112 && lcData.size() >= 112) {
                guardFlags = readU32LE(&lcData[108]);
            }
            if (structSize >= 128 && lcData.size() >= 128) {
                guardCFFunctionTable = readU64LE(&lcData[120]);
                guardCFFunctionCount = readU32LE(&lcData[128]);
            }
            if (structSize >= 144 && lcData.size() >= 144) {
                guardCFCheckFunctionPointer = readU64LE(&lcData[136]);
                guardCFDispatchFunctionPointer = readU64LE(&lcData[144]);
            }
            if (structSize >= 168 && lcData.size() >= 168) {
                guardRFFunctionTable = readU64LE(&lcData[160]);
                guardRFFunctionCount = readU32LE(&lcData[168]);
            }
        } else {
            // PE32 Load Config Directory layout
            if (structSize >= 96 && lcData.size() >= 96) {
                guardFlags = readU32LE(&lcData[92]);
            }
            if (structSize >= 108 && lcData.size() >= 108) {
                guardCFFunctionTable = static_cast<uint64_t>(readU32LE(&lcData[100]));
                guardCFFunctionCount = readU32LE(&lcData[108]);
            }
            if (structSize >= 120 && lcData.size() >= 120) {
                guardCFCheckFunctionPointer = static_cast<uint64_t>(readU32LE(&lcData[112]));
                guardCFDispatchFunctionPointer = static_cast<uint64_t>(readU32LE(&lcData[120]));
            }
            if (structSize >= 136 && lcData.size() >= 136) {
                guardRFFunctionTable = static_cast<uint64_t>(readU32LE(&lcData[128]));
                guardRFFunctionCount = readU32LE(&lcData[136]);
            }
        }

        // Create labels for Guard CFG metadata
        if (guardFlags != 0) {
            std::string flagStr = guardFlagsToString(guardFlags);
            symTable->createLabel(loadConfigAddr, "PE_GUARD_CFG_FLAGS_" + flagStr, SourceType::ANALYSIS);
        }

        if (guardCFFunctionTable != 0) {
            Address tableAddr(defaultSpace, static_cast<int64_t>(guardCFFunctionTable));
            if (memory->getBlock(tableAddr)) {
                std::string label = "GuardCF_FunctionTable_" + std::to_string(guardCFFunctionCount) + "entries";
                symTable->createLabel(tableAddr, label, SourceType::ANALYSIS);
            }
        }

        if (guardCFCheckFunctionPointer != 0) {
            Address checkAddr(defaultSpace, static_cast<int64_t>(guardCFCheckFunctionPointer));
            if (memory->getBlock(checkAddr)) {
                symTable->createLabel(checkAddr, "_guard_check_icall", SourceType::ANALYSIS);
            }
        }

        if (guardCFDispatchFunctionPointer != 0) {
            Address dispatchAddr(defaultSpace, static_cast<int64_t>(guardCFDispatchFunctionPointer));
            if (memory->getBlock(dispatchAddr)) {
                symTable->createLabel(dispatchAddr, "_guard_dispatch_icall", SourceType::ANALYSIS);
            }
        }

        if (guardRFFunctionTable != 0) {
            Address rfTableAddr(defaultSpace, static_cast<int64_t>(guardRFFunctionTable));
            if (memory->getBlock(rfTableAddr)) {
                std::string label = "GuardRF_FunctionTable_" + std::to_string(guardRFFunctionCount) + "entries";
                symTable->createLabel(rfTableAddr, label, SourceType::ANALYSIS);
            }
        }

        // Parse Guard CF function table if present
        // Each entry is 4 bytes (RVA of the function) for CF, or 8 bytes (RVA+flags) for RF
        if (guardCFFunctionTable != 0 && guardCFFunctionCount > 0 && guardCFFunctionCount < 0x100000) {
            Address tableAddr(defaultSpace, static_cast<int64_t>(guardCFFunctionTable));
            if (memory->getBlock(tableAddr)) {
                int tableReadSize = static_cast<int>(guardCFFunctionCount * 4);
                std::vector<uint8_t> tableData(static_cast<size_t>(tableReadSize));
                if (memory->getBytes(tableAddr, tableData.data(), tableReadSize) == tableReadSize) {
                    int validCount = 0;
                    for (uint32_t ti = 0; ti < guardCFFunctionCount; ++ti) {
                        uint32_t funcRVA = readU32LE(&tableData[ti * 4]);
                        if (funcRVA == 0) continue;
                        Address funcAddr(defaultSpace, static_cast<int64_t>(funcRVA));
                        if (memory->getBlock(funcAddr)) {
                            symTable->createLabel(funcAddr, "GuardCF_Target_" + std::to_string(ti),
                                                  SourceType::ANALYSIS);
                            ++validCount;
                        }
                    }
                    if (validCount > 0) {
                        Msg::info(getName(), "Guard CFG: Mapped " + std::to_string(validCount) +
                                  " valid call targets from function table");
                    }
                }
            }
        }

        // Report Guard CFG status
        if (guardCfgEnabled || guardFlags != 0) {
            std::string status = "PE Guard CFG enabled";
            if (guardFlags != 0) status += " (flags: " + guardFlagsToString(guardFlags) + ")";
            if (guardCFFunctionTable != 0) status += ", " + std::to_string(guardCFFunctionCount) + " CF targets";
            if (guardRFFunctionTable != 0) status += ", " + std::to_string(guardRFFunctionCount) + " RF targets";
            Msg::info(getName(), status);
            log.append(getName(), status);
        }

        // Only process first PE header found
        break;
    }

    std::cerr << "[GuardCfgAnalyzer] Done: " << blocksScanned << " blocks scanned, "
              << peFound << " PE headers found" << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[GuardCfgAnalyzer] EXCEPTION: " << e.what() << std::endl;
        Msg::error(getName(), "Guard CFG Analyzer error: " + std::string(e.what()));
    } catch (...) {
        std::cerr << "[GuardCfgAnalyzer] UNKNOWN EXCEPTION during analysis" << std::endl;
        Msg::error(getName(), "Guard CFG Analyzer: unknown error");
    }

    return true;
}

} // namespace ghidra
