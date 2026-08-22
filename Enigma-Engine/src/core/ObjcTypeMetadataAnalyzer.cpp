#include <ghidra/ObjcTypeMetadataAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <algorithm>

namespace ghidra {

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

ObjcTypeMetadataAnalyzer::ObjcTypeMetadataAnalyzer()
    : AbstractAnalyzer("Objective-C Type Metadata Analyzer",
                       "Discovers Objective-C type metadata records.",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FORMAT_ANALYSIS);
    setSupportsOneTimeAnalysis(true);
}

bool ObjcTypeMetadataAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;

    if (program->getLanguage()) {
        std::string procName = program->getLanguage()->getProcessor().getName();
        std::string lowerProc = procName;
        std::transform(lowerProc.begin(), lowerProc.end(), lowerProc.begin(), ::tolower);
        if (lowerProc == "aarch64" || lowerProc.find("arm") != std::string::npos) {
            return true;
        }
    }

    const std::string& format = program->getExecutableFormat();
    std::string lowerFormat = format;
    std::transform(lowerFormat.begin(), lowerFormat.end(), lowerFormat.begin(), ::tolower);
    if (lowerFormat.find("mach-o") != std::string::npos ||
        lowerFormat.find("macho") != std::string::npos) {
        return true;
    }

    return false;
}

bool ObjcTypeMetadataAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();
    AddressSpace* defaultSpace = program->getLanguage()->getDefaultSpace();
    if (!memory || !listing || !symTable || !defaultSpace) return true;

    bool is64 = (defaultSpace->getSize() == 64);
    int ptrSize = is64 ? 8 : 4;
    int classStructSize = ptrSize * 5;

    int totalClasses = 0;
    int totalProtocols = 0;
    int totalCategories = 0;

    for (auto* block : memory->getBlocks()) {
        if (monitor && monitor->isCancelled()) break;

        std::string blockName = block->getName();
        bool isClassList = blockName.find("__objc_classlist") != std::string::npos ||
                           blockName.find("objc_classlist") != std::string::npos;
        bool isProtoList = blockName.find("__objc_protolist") != std::string::npos ||
                           blockName.find("objc_protolist") != std::string::npos;
        bool isCatList = blockName.find("__objc_catlist") != std::string::npos ||
                         blockName.find("objc_catlist") != std::string::npos;
        bool isSelRefs = blockName.find("__objc_selrefs") != std::string::npos ||
                         blockName.find("objc_selrefs") != std::string::npos;
        bool isClassRefs = blockName.find("__objc_classrefs") != std::string::npos ||
                           blockName.find("objc_classrefs") != std::string::npos;

        if (!isClassList && !isProtoList && !isCatList && !isSelRefs && !isClassRefs) continue;

        Address blockStart = block->getStart();
        int64_t blockSize = block->getEnd().getOffset() - blockStart.getOffset() + 1;

        if (blockSize < static_cast<int64_t>(ptrSize)) continue;

        std::vector<uint8_t> data(static_cast<size_t>(blockSize));
        if (memory->getBytes(blockStart, data.data(), static_cast<int>(blockSize))
            != static_cast<int>(blockSize)) continue;

        int maxEntries = static_cast<int>(blockSize / ptrSize);
        for (int i = 0; i < maxEntries; ++i) {
            if (monitor && monitor->isCancelled()) break;

            uint64_t ptrVal;
            if (is64) {
                ptrVal = readU64LE(&data[static_cast<size_t>(i * ptrSize)]);
            } else {
                ptrVal = readU32LE(&data[static_cast<size_t>(i * ptrSize)]);
            }
            if (ptrVal == 0) continue;

            Address targetAddr(defaultSpace, static_cast<int64_t>(ptrVal));
            if (!memory->getBlock(targetAddr)) continue;

            if (isClassList || isClassRefs) {
                std::string className;
                std::vector<uint8_t> classBuf(static_cast<size_t>(classStructSize));
                if (memory->getBytes(targetAddr, classBuf.data(), classStructSize)
                    != classStructSize) continue;

                uint64_t dataPtr;
                if (is64) {
                    dataPtr = readU64LE(&classBuf[static_cast<size_t>(ptrSize * 4)]);
                } else {
                    dataPtr = readU32LE(&classBuf[static_cast<size_t>(ptrSize * 4)]);
                }
                if (dataPtr == 0) continue;

                Address roAddr(defaultSpace, static_cast<int64_t>(dataPtr));
                if (!memory->getBlock(roAddr)) continue;

                int roReadSize = is64 ? 64 : 48;
                std::vector<uint8_t> roData(static_cast<size_t>(roReadSize));
                if (memory->getBytes(roAddr, roData.data(), roReadSize) != roReadSize) continue;

                // Scan class_ro_t for a name pointer
                int nameFieldStart = is64 ? 16 : 12;
                int nameFieldEnd = is64 ? 40 : 28;
                int nameFieldStep = is64 ? 8 : 4;

                for (int checkOff = nameFieldStart; checkOff <= nameFieldEnd; checkOff += nameFieldStep) {
                    uint64_t candidateName;
                    if (is64) {
                        candidateName = readU64LE(&roData[static_cast<size_t>(checkOff)]);
                    } else {
                        candidateName = readU32LE(&roData[static_cast<size_t>(checkOff)]);
                    }
                    if (candidateName == 0) continue;

                    Address nameAddr(defaultSpace, static_cast<int64_t>(candidateName));
                    MemoryBlock* nameBlock = memory->getBlock(nameAddr);
                    if (!nameBlock) continue;

                    uint8_t nameBuf[128];
                    int nameMax = static_cast<int>(std::min(static_cast<int64_t>(sizeof(nameBuf) - 1),
                                             nameBlock->getEnd().getOffset() - nameAddr.getOffset() + 1));
                    if (nameMax < 4) continue;
                    if (memory->getBytes(nameAddr, nameBuf, nameMax) != nameMax) continue;

                    bool validName = true;
                    int nameLen = 0;
                    for (int ni = 0; ni < nameMax; ++ni) {
                        if (nameBuf[ni] == 0) break;
                        ++nameLen;
                        if (!std::isalnum(nameBuf[ni]) && nameBuf[ni] != '_' && nameBuf[ni] != ':') {
                            validName = false;
                            break;
                        }
                    }
                    if (validName && nameLen >= 2 && nameLen < 100) {
                        className.assign(reinterpret_cast<char*>(nameBuf), static_cast<size_t>(nameLen));
                        break;
                    }
                }

                if (isClassList) {
                    std::string label = className.empty()
                        ? ("OBJC_CLASS_$_unknown_" + std::to_string(totalClasses))
                        : ("OBJC_CLASS_$_" + className);
                    symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
                    ++totalClasses;
                } else if (!className.empty()) {
                    std::string label = "OBJC_CLASSREF_$_" + className;
                    symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
                }
            } else if (isProtoList) {
                // Try to resolve protocol name from protocol_t structure
                std::string protoName;
                int protoStructSize = is64 ? 48 : 32;
                std::vector<uint8_t> protoBuf(static_cast<size_t>(protoStructSize));
                if (memory->getBytes(targetAddr, protoBuf.data(), protoStructSize) == protoStructSize) {
                    // protocol_t->mangledName is at offset ptrSize*2 (after isa, flags)
                    int nameOff = is64 ? 16 : 8;
                    uint64_t namePtr;
                    if (is64) {
                        namePtr = readU64LE(&protoBuf[nameOff]);
                    } else {
                        namePtr = readU32LE(&protoBuf[nameOff]);
                    }
                    if (namePtr != 0) {
                        Address nameAddr(defaultSpace, static_cast<int64_t>(namePtr));
                        if (memory->getBlock(nameAddr)) {
                            uint8_t nameBuf[128];
                            int nameMax = static_cast<int>(std::min(static_cast<int64_t>(sizeof(nameBuf) - 1),
                                                        nameAddr.getOffset() < memory->getBlock(nameAddr)->getEnd().getOffset()
                                                        ? memory->getBlock(nameAddr)->getEnd().getOffset() - nameAddr.getOffset() + 1
                                                        : static_cast<int64_t>(0)));
                            if (nameMax >= 2) {
                                if (memory->getBytes(nameAddr, nameBuf, nameMax) == nameMax) {
                                    bool validName = true;
                                    int nameLen = 0;
                                    for (int ni = 0; ni < nameMax; ++ni) {
                                        if (nameBuf[ni] == 0) break;
                                        ++nameLen;
                                        if (!std::isalnum(nameBuf[ni]) && nameBuf[ni] != '_' && nameBuf[ni] != ' ') {
                                            validName = false;
                                            break;
                                        }
                                    }
                                    if (validName && nameLen >= 2 && nameLen < 100) {
                                        protoName.assign(reinterpret_cast<char*>(nameBuf), static_cast<size_t>(nameLen));
                                    }
                                }
                            }
                        }
                    }
                }
                std::string label = protoName.empty()
                    ? ("OBJC_PROTOCOL_$_" + std::to_string(totalProtocols))
                    : ("OBJC_PROTOCOL_$_" + protoName);
                symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
                ++totalProtocols;
            } else if (isCatList) {
                // Try to resolve category name from category_t structure
                std::string catName;
                std::string catClassName;
                int catStructSize = is64 ? 40 : 24;
                std::vector<uint8_t> catBuf(static_cast<size_t>(catStructSize));
                if (memory->getBytes(targetAddr, catBuf.data(), catStructSize) == catStructSize) {
                    // category_t layout:
                    // offset 0: name (char*)
                    // offset ptrSize: cls (classref_t)
                    // offset ptrSize*2: instanceMethods
                    // offset ptrSize*3: classMethods
                    // offset ptrSize*4: protocols (32-bit) or protocols+instanceProperties (64-bit)
                    int nameOff = 0;
                    int clsOff = is64 ? 8 : 4;

                    // Read category name
                    uint64_t catNamePtr;
                    if (is64) {
                        catNamePtr = readU64LE(&catBuf[nameOff]);
                    } else {
                        catNamePtr = readU32LE(&catBuf[nameOff]);
                    }
                    if (catNamePtr != 0) {
                        Address nameAddr(defaultSpace, static_cast<int64_t>(catNamePtr));
                        if (memory->getBlock(nameAddr)) {
                            uint8_t nameBuf[128];
                            int nameMax = 128;
                            if (memory->getBytes(nameAddr, nameBuf, nameMax) > 0) {
                                bool validName = true;
                                int nameLen = 0;
                                for (int ni = 0; ni < nameMax; ++ni) {
                                    if (nameBuf[ni] == 0) break;
                                    ++nameLen;
                                    if (!std::isalnum(nameBuf[ni]) && nameBuf[ni] != '_' && nameBuf[ni] != ' ') {
                                        validName = false;
                                        break;
                                    }
                                }
                                if (validName && nameLen >= 1 && nameLen < 100) {
                                    catName.assign(reinterpret_cast<char*>(nameBuf), static_cast<size_t>(nameLen));
                                }
                            }
                        }
                    }

                    // Read class reference
                    uint64_t clsPtr;
                    if (is64) {
                        clsPtr = readU64LE(&catBuf[clsOff]);
                    } else {
                        clsPtr = readU32LE(&catBuf[clsOff]);
                    }
                    if (clsPtr != 0) {
                        Address clsAddr(defaultSpace, static_cast<int64_t>(clsPtr));
                        if (memory->getBlock(clsAddr)) {
                            // Try to resolve class name from the class reference
                            std::vector<uint8_t> clsRefBuf(static_cast<size_t>(classStructSize));
                            if (memory->getBytes(clsAddr, clsRefBuf.data(), classStructSize) == classStructSize) {
                                uint64_t dataPtr;
                                if (is64) {
                                    dataPtr = readU64LE(&clsRefBuf[ptrSize * 4]);
                                } else {
                                    dataPtr = readU32LE(&clsRefBuf[ptrSize * 4]);
                                }
                                if (dataPtr != 0) {
                                    Address roAddr(defaultSpace, static_cast<int64_t>(dataPtr));
                                    if (memory->getBlock(roAddr)) {
                                        std::vector<uint8_t> roData(64);
                                        if (memory->getBytes(roAddr, roData.data(), 64) == 64) {
                                            int nameFieldStart = is64 ? 16 : 12;
                                            for (int checkOff = nameFieldStart; checkOff < (is64 ? 40 : 28); checkOff += (is64 ? 8 : 4)) {
                                                uint64_t candidateName;
                                                if (is64) {
                                                    candidateName = readU64LE(&roData[checkOff]);
                                                } else {
                                                    candidateName = readU32LE(&roData[checkOff]);
                                                }
                                                if (candidateName == 0) continue;
                                                Address nameAddr2(defaultSpace, static_cast<int64_t>(candidateName));
                                                if (!memory->getBlock(nameAddr2)) continue;
                                                uint8_t nameBuf2[128];
                                                if (memory->getBytes(nameAddr2, nameBuf2, sizeof(nameBuf2) - 1) <= 0) continue;
                                                bool validName = true;
                                                int nameLen = 0;
                                                for (int ni = 0; ni < 127; ++ni) {
                                                    if (nameBuf2[ni] == 0) break;
                                                    ++nameLen;
                                                    if (!std::isalnum(nameBuf2[ni]) && nameBuf2[ni] != '_') {
                                                        validName = false;
                                                        break;
                                                    }
                                                }
                                                if (validName && nameLen >= 2 && nameLen < 100) {
                                                    catClassName.assign(reinterpret_cast<char*>(nameBuf2), static_cast<size_t>(nameLen));
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                std::string label;
                if (!catClassName.empty() && !catName.empty()) {
                    label = "OBJC_CATEGORY_$_" + catClassName + "(" + catName + ")";
                } else if (!catName.empty()) {
                    label = "OBJC_CATEGORY_$_" + catName;
                } else {
                    label = "OBJC_CATEGORY_$_" + std::to_string(totalCategories);
                }
                symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
                ++totalCategories;
            }
        }

        if (isSelRefs) {
            for (int i = 0; i < maxEntries; ++i) {
                if (monitor && monitor->isCancelled()) break;

                uint64_t selPtr;
                if (is64) {
                    selPtr = readU64LE(&data[static_cast<size_t>(i * ptrSize)]);
                } else {
                    selPtr = readU32LE(&data[static_cast<size_t>(i * ptrSize)]);
                }
                if (selPtr == 0) continue;

                Address selAddr(defaultSpace, static_cast<int64_t>(selPtr));
                if (!memory->getBlock(selAddr)) continue;

                uint8_t selBuf[128];
                int bytesRead = memory->getBytes(selAddr, selBuf, static_cast<int>(sizeof(selBuf) - 1));
                if (bytesRead <= 0) continue;

                std::string selName;
                bool validSel = true;
                for (int si = 0; si < bytesRead; ++si) {
                    if (selBuf[si] == 0) break;
                    unsigned char c = selBuf[si];
                    if (!std::isprint(c)) { validSel = false; break; }
                    selName += static_cast<char>(c);
                }
                if (validSel && !selName.empty()) {
                    Address refAddr = blockStart.add(static_cast<int64_t>(i * ptrSize));
                    std::string label = "sel_" + selName;
                    symTable->createLabel(refAddr, label, SourceType::ANALYSIS);
                }
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(totalClasses) +
                            " classes, " + std::to_string(totalProtocols) +
                            " protocols, " + std::to_string(totalCategories) + " categories");
    }

    if (totalClasses > 0) {
        Msg::info(getName(), "Discovered " + std::to_string(totalClasses) + " ObjC classes");
    }

    return true;
}

} // namespace ghidra
