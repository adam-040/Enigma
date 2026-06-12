#include <ghidra/GolangSymbolAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>

namespace ghidra {

static const char* OUTPUT_SOURCE_INFO_OPTIONNAME = "Output Source Info";
static const char* OUTPUT_SOURCE_INFO_DESC = R"(
Add "source_file_name:line_number" information to functions.)";

static const char* FIXUP_DUFF_FUNCS_OPTIONNAME = "Fixup Duff Functions";
static const char* FIXUP_DUFF_FUNCS_DESC = R"(
Copies information from the runtime.duffzero and runtime.duffcopy functions to \
the alternate duff entry points that are discovered during later analysis.)";

static const char* PROP_RTTI_OPTIONNAME = "Propagate RTTI";
static const char* PROP_RTTI_DESC = R"(
Override the function signature of calls to some built-in Go allocator \
functions that have a constant reference to a Go type record.)";

static const char* FIXUP_GCWRITEBARRIER_OPTIONNAME = "Fixup gcWriteBarrier Functions";
static const char* FIXUP_GCWRITEBARRIER_FUNCS_DESC = R"(
Fixup gcWriteBarrier functions \
(requires gcwrite calling convention defined for the program's arch))";

static const char* FIXUP_GCWRITEBARRIER_FLAG_OPTIONNAME = "Fixup gcWriteBarrier Flag";
static const char* FIXUP_GCWRITEBARRIER_FLAG_DESC = R"(
Fixup global writeBarrier flag so decompiler can eliminate some code paths.)";

static const char* FALLBACK_GOVER_OPTIONNAME = "Fallback Go Version";
static const char* FALLBACK_GOVER_DESC = R"(
Go version to use if the Go metadata has been obfuscated.)";

static const uint32_t PCHEADER_MAGIC = 0xFFFFFFF0;

static uint32_t readU32LE(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 0) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static uint64_t readU64LE(const uint8_t* p) {
    return (static_cast<uint64_t>(p[0]) << 0) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

static int32_t readS32LE(const uint8_t* p) {
    uint32_t v = readU32LE(p);
    return static_cast<int32_t>(v);
}

static bool isValidGoFuncName(const std::string& name) {
    if (name.empty() || name.size() > 256) return false;
    int dotCount = 0;
    for (size_t i = 0; i < name.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(name[i]);
        if (c == '.') ++dotCount;
        else if (!std::isalnum(c) && c != '/' && c != '-' && c != '_' && c != '(' &&
                 c != ')' && c != '*' && c != '[' && c != ']') {
            return false;
        }
    }
    return dotCount >= 1;
}

GolangSymbolAnalyzer::GolangSymbolAnalyzer()
    : AbstractAnalyzer("Golang Symbols",
                       "Analyze Go binaries for RTTI and function symbols.\n"
                       "'Apply Data Archives' and 'Shared Return Calls' analyzers should be disabled "
                       "for best results.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after());
    setDefaultEnablement(true);
}

bool GolangSymbolAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    Language* lang = program->getLanguage();
    if (!lang) return false;
    std::string langId = lang->getLanguageID().toString();
    return langId.find("Golang") != std::string::npos || langId.find("golang") != std::string::npos;
}

void GolangSymbolAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OUTPUT_SOURCE_INFO_OPTIONNAME, true, OUTPUT_SOURCE_INFO_DESC);
    options.registerBool(FIXUP_DUFF_FUNCS_OPTIONNAME, true, FIXUP_DUFF_FUNCS_DESC);
    options.registerBool(PROP_RTTI_OPTIONNAME, true, PROP_RTTI_DESC);
    options.registerBool(FIXUP_GCWRITEBARRIER_OPTIONNAME, true, FIXUP_GCWRITEBARRIER_FUNCS_DESC);
    options.registerBool(FIXUP_GCWRITEBARRIER_FLAG_OPTIONNAME, true, FIXUP_GCWRITEBARRIER_FLAG_DESC);
    options.registerString(FALLBACK_GOVER_OPTIONNAME, "", FALLBACK_GOVER_DESC);
}

void GolangSymbolAnalyzer::optionsChanged(Options& options, Program* program) {
}

bool GolangSymbolAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    AddressSpace* defaultSpace = program->getLanguage()->getDefaultSpace();
    if (!memory || !symTable || !listing || !defaultSpace) return true;

    bool is64 = (defaultSpace->getSize() == 64);
    int ptrSize = is64 ? 8 : 4;
    uint64_t maxPtrVal = is64 ? (~0ULL) : 0xFFFFFFFFULL;

    int totalFuncs = 0;
    int totalNames = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;

        std::string blockName = block->getName();
        bool isPclnSection = (blockName.find("gopclntab") != std::string::npos ||
                              blockName.find("gopcln") != std::string::npos ||
                              blockName.find("pclntab") != std::string::npos);

        Address blockStart = block->getStart();
        Address blockEnd = block->getEnd();
        int64_t blockSize = blockEnd.getOffset() - blockStart.getOffset() + 1;
        if (blockSize < 16) continue;

        if (monitor) monitor->setMessage(getName() + ": Scanning " + blockName);

        std::vector<uint8_t> data(static_cast<size_t>(blockSize));
        if (memory->getBytes(blockStart, data.data(), static_cast<int>(blockSize))
            != static_cast<int>(blockSize)) continue;

        // Scan for pclntab magic
        for (int64_t off = 0; off + 16 <= static_cast<int64_t>(blockSize); ++off) {
            if (monitor && monitor->isCancelled()) break;
            if (off % 65536 == 0) monitor->setProgress(static_cast<int>(off));

            uint32_t magic = readU32LE(&data[static_cast<size_t>(off)]);
            if (magic != PCHEADER_MAGIC) continue;

            // Found potential pclntab
            // Check header bytes: pad1=0, minLC=1 or 2, ptrSize=4 or 8
            uint8_t pad1 = data[static_cast<size_t>(off + 4)];
            uint8_t minLC = data[static_cast<size_t>(off + 5)];
            uint8_t ptrSizeByte = data[static_cast<size_t>(off + 6)];
            if (pad1 != 0) continue;
            if (minLC != 1 && minLC != 2) continue;
            if (ptrSizeByte != 4 && ptrSizeByte != 8) continue;
            if (static_cast<int>(ptrSizeByte) != ptrSize) continue;

            int pcHeaderWords = -1;
            uint64_t nfunc = 0;
            uint64_t textStart = 0;
            uint64_t funcnameOffset = 0;

            // Try Go 1.18+ format first (no headerSize field)
            // For Go 1.18+ 64-bit: offset 7 is start of "int" nfunc
            // header is: magic(4) + pad1(1) + minLC(1) + ptrSize(1) = 7 bytes
            // Then nfunc(int64) = 8 bytes starting at offset 7
            // But byte 7 should be 0 if headerSize existed, or non-zero if nfunc starts
            if (off + 7 + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                uint64_t nfunc1;
                if (is64) {
                    nfunc1 = readU64LE(&data[static_cast<size_t>(off + 7)]);
                } else {
                    nfunc1 = readU32LE(&data[static_cast<size_t>(off + 7)]);
                }
                if (nfunc1 > 0 && nfunc1 < 100000) {
                    // Check if byte at offset 7 looks like nfunc (not headerSize)
                    uint8_t nextField1 = data[static_cast<size_t>(off + 7 + ptrSize)];
                    // Guess: headerSize was removed in Go 1.18, so offset 7 has nfunc
                    pcHeaderWords = 11;
                    nfunc = nfunc1;
                    if (off + 7 + static_cast<int64_t>(ptrSize * 2) <= static_cast<int64_t>(blockSize)) {
                        // uint64_t nfiles
                    }
                }
            }

            // Try Go 1.16-1.17 format (has headerSize at byte 7)
            // header = magic(4) + pad1(1) + minLC(1) + ptrSize(1) + headerSize(1) + nfunc(8 on 64-bit)
            if (pcHeaderWords < 0 && off + 8 + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                uint8_t headerSize = data[static_cast<size_t>(off + 7)];
                if (headerSize >= 7 && headerSize <= 15) {
                    int nfuncOff = 8;
                    if (off + nfuncOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                        uint64_t nfunc2;
                        if (is64) {
                            nfunc2 = readU64LE(&data[static_cast<size_t>(off + nfuncOff)]);
                        } else {
                            nfunc2 = readU32LE(&data[static_cast<size_t>(off + nfuncOff)]);
                        }
                        if (nfunc2 > 0 && nfunc2 < 100000) {
                            pcHeaderWords = static_cast<int>(headerSize);
                            nfunc = nfunc2;
                        }
                    }
                }
            }

            if (pcHeaderWords < 0) continue;

            // pcHeaderWords tells us the header size in words (ptrSize bytes each)
            int pcHeaderBytes = pcHeaderWords * ptrSize;
            if (off + pcHeaderBytes + static_cast<int64_t>(ptrSize * 2) > static_cast<int64_t>(blockSize)) continue;

            // Extract key fields from pcHeader
            // Layout (for 64-bit Go 1.16+):
            // 0: magic(4), 4: pad1(1), 5: minLC(1), 6: ptrSize(1), 7: headerSize(1)
            // 8: nfunc(8), 16: nfiles(8), 24: textStart(8)
            // 32: funcnameOffset(8), 40: cuOffset(8), 48: filetabOffset(8)
            // 56: pctabOffset(8), 64: pclnOffset(8)

            int fieldOff = 8;
            if (off + fieldOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                // Already have nfunc
            }
            fieldOff += ptrSize; // skip nfunc
            if (off + fieldOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                // uint64_t nfiles (skip)
            }
            fieldOff += ptrSize; // skip nfiles
            if (off + fieldOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                if (is64) {
                    textStart = readU64LE(&data[static_cast<size_t>(off + fieldOff)]);
                } else {
                    textStart = readU32LE(&data[static_cast<size_t>(off + fieldOff)]);
                }
            }
            fieldOff += ptrSize; // skip textStart
            if (off + fieldOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize)) {
                if (is64) {
                    funcnameOffset = readU64LE(&data[static_cast<size_t>(off + fieldOff)]);
                } else {
                    funcnameOffset = readU32LE(&data[static_cast<size_t>(off + fieldOff)]);
                }
            }

            if (textStart == 0 || funcnameOffset == 0) {
                // Might have guessed wrong header size, try another layout
                Msg::debug(getName(), "Could not determine pclntab layout at offset " + std::to_string(off));
                continue;
            }

            // Find textStart block to verify
            Address textStartAddr(defaultSpace, static_cast<int64_t>(textStart));
            if (!memory->getBlock(textStartAddr)) {
                // textStart is not in a known block; pclntab might be at wrong offset
                continue;
            }

            // Found valid pclntab
            // Now parse funcTab which starts right after pcHeader
            int funcTableOff = pcHeaderBytes;
            int funcTabEntrySize = ptrSize * 2; // {entry(uintptr), funcoff(uintptr)}

            uint64_t funcnameTableAddrVal = textStart + funcnameOffset;
            Address funcnameAddr(defaultSpace, static_cast<int64_t>(funcnameTableAddrVal));
            MemoryBlock* funcnameBlock = memory->getBlock(funcnameAddr);
            if (!funcnameBlock) continue;

            // Read funcname table content
            int64_t funcnameBlockOff = funcnameAddr.getOffset() - funcnameBlock->getStart().getOffset();
            int64_t funcnameBlockSize = funcnameBlock->getEnd().getOffset() - funcnameBlock->getStart().getOffset() + 1;
            if (funcnameBlockOff < 0 || funcnameBlockOff >= funcnameBlockSize) continue;

            int64_t availFuncname = funcnameBlockSize - funcnameBlockOff;
            if (availFuncname < 16) continue;

            std::vector<uint8_t> funcnameData(static_cast<size_t>(availFuncname));
            if (memory->getBytes(funcnameAddr, funcnameData.data(), static_cast<int>(availFuncname))
                != static_cast<int>(availFuncname)) continue;

            for (uint64_t fi = 0; fi < nfunc && fi < 50000; ++fi) {
                if (monitor && monitor->isCancelled()) break;

                int entryOff = funcTableOff + static_cast<int>(fi * funcTabEntrySize);
                if (entryOff + funcTabEntrySize > static_cast<int>(blockSize)) break;

                uint64_t functionEntry = 0;
                uint64_t funcoff = 0;

                if (is64) {
                    functionEntry = readU64LE(&data[static_cast<size_t>(off + entryOff)]);
                    funcoff = readU64LE(&data[static_cast<size_t>(off + entryOff + ptrSize)]);
                } else {
                    functionEntry = readU32LE(&data[static_cast<size_t>(off + entryOff)]);
                    funcoff = readU32LE(&data[static_cast<size_t>(off + entryOff + ptrSize)]);
                }

                // Validate function entry
                if (functionEntry == 0 || functionEntry > maxPtrVal) continue;
                if (funcoff == 0 || funcoff + 8 > static_cast<uint64_t>(blockSize)) continue;

                // _func struct at pclntab + funcoff
                uint64_t funcInfoOff = static_cast<uint64_t>(off) + funcoff;
                if (funcInfoOff + 8 > static_cast<uint64_t>(blockSize)) continue;

                // Read _func.entryOff (uint32) and _func.nameOff (int32)
                uint32_t funcEntryOff = readU32LE(&data[static_cast<size_t>(funcInfoOff)]);
                int32_t funcNameOff = readS32LE(&data[static_cast<size_t>(funcInfoOff + 4)]);

                uint64_t actualEntry = static_cast<uint64_t>(funcEntryOff) + textStart;
                if (actualEntry != functionEntry) {
                    // The funcTab entry is the resolved address;
                    // _func.entryOff is an offset from textStart
                    actualEntry = functionEntry;
                    (void)funcEntryOff; // Keep using funcTab's entry
                }

                // Validate entry address
                Address entryAddr(defaultSpace, static_cast<int64_t>(actualEntry));
                MemoryBlock* entryBlock = memory->getBlock(entryAddr);
                if (!entryBlock) continue;
                if (entryBlock->isExecute() == false && entryBlock->isRead() == false) continue;

                // Get function name from funcname table
                int32_t nameStrOff = funcNameOff;
                if (nameStrOff < 0 || static_cast<int64_t>(nameStrOff) >= availFuncname) continue;

                // Read null-terminated string from funcname table
                std::string funcName;
                int64_t nameMaxLen = std::min(static_cast<int64_t>(256), availFuncname - static_cast<int64_t>(nameStrOff));
                for (int64_t ni = 0; ni < nameMaxLen; ++ni) {
                    char c = static_cast<char>(funcnameData[static_cast<size_t>(nameStrOff + ni)]);
                    if (c == '\0') break;
                    funcName += c;
                }

                if (funcName.empty() || !isValidGoFuncName(funcName)) continue;

                // Create label at function entry
                if (!listing->isUndefined(entryAddr)) continue;

                symTable->createLabel(entryAddr, funcName, SourceType::ANALYSIS);
                ++totalFuncs;
                ++totalNames;
            }

            if (totalFuncs > 0) {
                Msg::info(getName(), "Parsed pclntab at " + blockStart.add(off).toString() +
                          ": " + std::to_string(totalFuncs) + " functions labeled");
            }
            break; // Only process first valid pclntab
        }
    }

    // Fall back to scanning for Go function name patterns if pclntab approach found nothing
    if (totalFuncs == 0) {
        if (monitor) monitor->setMessage(getName() + ": Falling back to pattern-based symbol scan");

        for (auto* block : memory->getBlocks()) {
            if (monitor && monitor->isCancelled()) break;

            std::string blockName = block->getName();
            if (blockName.find(".data") == std::string::npos &&
                blockName.find("rodata") == std::string::npos) continue;

            Address blockStart = block->getStart();
            int64_t blockSize = block->getEnd().getOffset() - blockStart.getOffset() + 1;
            if (blockSize < 32) continue;

            std::vector<uint8_t> data(static_cast<size_t>(blockSize));
            if (memory->getBytes(blockStart, data.data(), static_cast<int>(blockSize))
                != static_cast<int>(blockSize)) continue;

            for (int64_t off = 0; off < static_cast<int64_t>(blockSize); ) {
                if (monitor && monitor->isCancelled()) break;

                // Check for Go function name pattern: at least one dot, no special chars
                int64_t maxScan = std::min(static_cast<int64_t>(blockSize) - off, static_cast<int64_t>(256));
                std::string candidate;
                for (int64_t si = 0; si < maxScan; ++si) {
                    char c = static_cast<char>(data[static_cast<size_t>(off + si)]);
                    if (c == '\0') break;
                    candidate += c;
                }

                if (candidate.size() >= 4 && isValidGoFuncName(candidate) &&
                    candidate.find("..") == std::string::npos &&
                    candidate.front() != '.' && candidate.back() != '.') {

                    // Found a Go function name string
                    // Look for pointer to this string from code
                    uint64_t strAddr = static_cast<uint64_t>(blockStart.getOffset() + off);

                    // Check nearby addresses for a pointer to this string
                    for (int64_t scanOff = off - 256; scanOff < off + 256 && scanOff >= 0 &&
                         scanOff + static_cast<int64_t>(ptrSize) <= static_cast<int64_t>(blockSize); ) {
                        if (monitor && monitor->isCancelled()) break;

                        // Align to ptrSize
                        int64_t alignedOff = (scanOff / ptrSize) * ptrSize;
                        if (alignedOff < 0 || alignedOff + ptrSize > static_cast<int64_t>(blockSize)) {
                            scanOff = alignedOff + ptrSize;
                            continue;
                        }

                        uint64_t val;
                        if (is64) {
                            val = readU64LE(&data[static_cast<size_t>(alignedOff)]);
                        } else {
                            val = readU32LE(&data[static_cast<size_t>(alignedOff)]);
                        }

                        if (val == strAddr) {
                            // Found a reference to the string!
                            // Check if this looks like function data
                            Address refAddr(defaultSpace, static_cast<int64_t>(blockStart.getOffset() + alignedOff));

                            // Try to find the function entry by looking at nearby pointers
                            // In a _func struct, entryOff comes before nameOff
                            // Search around the reference for a valid-looking entry address
                            int64_t searchStart = std::max(alignedOff - 64, static_cast<int64_t>(0));
                            int64_t searchEnd = std::min(alignedOff + 64, static_cast<int64_t>(blockSize) - static_cast<int64_t>(ptrSize));

                            for (int64_t findOff = searchStart; findOff <= searchEnd; findOff += ptrSize) {
                                uint64_t entryVal;
                                if (is64) {
                                    entryVal = readU64LE(&data[static_cast<size_t>(findOff)]);
                                } else {
                                    entryVal = readU32LE(&data[static_cast<size_t>(findOff)]);
                                }

                                if (entryVal == 0 || entryVal >= maxPtrVal) continue;

                                Address possibleEntry(defaultSpace, static_cast<int64_t>(entryVal));
                                MemoryBlock* possibleBlock = memory->getBlock(possibleEntry);
                                if (possibleBlock && possibleBlock->isExecute()) {
                                    if (listing->isUndefined(possibleEntry)) {
                                        symTable->createLabel(possibleEntry, candidate, SourceType::ANALYSIS);
                                        ++totalFuncs;
                                        break;
                                    }
                                }
                            }
                        }
                        scanOff = alignedOff + ptrSize;
                    }
                }
                off += static_cast<int64_t>(candidate.size() + 1);
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(totalFuncs) +
                            " Go function symbols (" + std::to_string(totalNames) + " named)");
    }

    return true;
}

} // namespace ghidra
