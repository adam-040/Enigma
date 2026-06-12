#include <ghidra/DexExceptionHandlersAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/IntegerDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/WordDataType.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/Msg.h>
#include <ghidra/ULEB128.h>

#include <memory>
#include <vector>
#include <string>
#include <cstring>

namespace ghidra {

static bool isDex(Program* program) {
    if (!program || !program->getMemory()) return false;
    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);
    uint8_t magic[4] = {0};
    if (program->getMemory()->getBytes(addr, magic, 4) != 4) return false;
    return magic[0] == 0x64 && magic[1] == 0x65 && magic[2] == 0x78 && magic[3] == 0x0A;
}

static uint32_t r32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 0) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

static uint16_t r16(const uint8_t* p) {
    return (static_cast<uint16_t>(p[0]) << 0) |
           (static_cast<uint16_t>(p[1]) << 8);
}

DexExceptionHandlersAnalyzer::DexExceptionHandlersAnalyzer()
    : AbstractAnalyzer("Android DEX/CDEX Exception Handlers",
                       "Android DEX/CDEX Exception Handlers.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION);
    setDefaultEnablement(true);
}

bool DexExceptionHandlersAnalyzer::canAnalyze(Program* program) const {
    return isDex(program);
}

bool DexExceptionHandlersAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool DexExceptionHandlersAnalyzer::added(Program* program, const AddressSetView& set,
                                          TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    DataTypeManager* dtm = program->getDataTypeManager();
    SymbolTable* symTable = program->getSymbolTable();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !listing || !dtm || !symTable || !refMgr) return false;

    if (monitor) monitor->setMessage("Parsing DEX exception handlers...");

    auto space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());

    // Read DEX header (first 0x70 bytes)
    Address headerAddr(space, 0);
    uint8_t header[0x70];
    if (memory->getBytes(headerAddr, header, sizeof(header)) != sizeof(header)) return true;

    uint32_t classDefsOff = r32(&header[0x60]);
    uint32_t classDefsSize = r32(&header[0x5C]);
    uint32_t stringIdsOff = r32(&header[0x08]);
    uint32_t typeIdsOff = r32(&header[0x10]);
    uint32_t methodIdsOff = r32(&header[0x20]);
    uint32_t dataOff = r32(&header[0x6C]);

    // Read string IDs (array of uint32 offsets to string_data)
    Address stringIdsAddr(space, stringIdsOff);
    std::vector<uint8_t> stringIdData(static_cast<size_t>(classDefsSize > 0 ? 4 : 0)); // at least some
    if (classDefsSize > 0) {
        stringIdData.resize(static_cast<size_t>(std::max(stringIdsOff, classDefsOff + classDefsSize * 0x20)));
    } else {
        stringIdData.resize(static_cast<size_t>(dataOff > 0x70 ? dataOff - 0x70 : 0x1000));
    }

    // Read the full DEX file data
    uint32_t totalSize = r32(&header[0x08]); // fileSize
    if (totalSize < sizeof(header) || totalSize > 16 * 1024 * 1024) return true;

    std::vector<uint8_t> fileData(static_cast<size_t>(totalSize));
    if (memory->getBytes(headerAddr, fileData.data(), static_cast<int>(totalSize))
        != static_cast<int>(totalSize)) return true;

    int totalTryItems = 0;
    int totalHandlers = 0;

    // Iterate through class_defs
    for (uint32_t cdi = 0; cdi < classDefsSize; ++cdi) {
        if (monitor && monitor->isCancelled()) break;

        uint32_t classDefOffset = classDefsOff + cdi * 0x20;
        if (classDefOffset + 0x20 > totalSize) break;

        uint32_t classDataOff = r32(&fileData[static_cast<size_t>(classDefOffset + 0x14)]);
        if (classDataOff == 0) continue;

        if (monitor) {
            monitor->setMessage(getName() + ": Processing class_def #" + std::to_string(cdi));
        }

        // Parse class_data_item
        // Format: static_fields_size(uleb128), instance_fields_size(uleb128),
        //         direct_methods_size(uleb128), virtual_methods_size(uleb128)
        int pos = static_cast<int>(classDataOff);
        if (pos >= static_cast<int>(totalSize)) continue;

        // Skip field sizes (static + instance)
        readULEB128(fileData.data(), pos, static_cast<int>(totalSize)); // static_fields_size
        if (pos >= static_cast<int>(totalSize)) break;
        readULEB128(fileData.data(), pos, static_cast<int>(totalSize)); // instance_fields_size
        if (pos >= static_cast<int>(totalSize)) break;

        uint64_t directMethodsSize = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));
        if (pos >= static_cast<int>(totalSize)) break;
        uint64_t virtualMethodsSize = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));
        if (pos >= static_cast<int>(totalSize)) break;

        // Process direct methods
        for (uint64_t mi = 0; mi < directMethodsSize; ++mi) {
            if (monitor && monitor->isCancelled()) break;
            if (pos >= static_cast<int>(totalSize)) break;

            readULEB128(fileData.data(), pos, static_cast<int>(totalSize)); // method_idx_diff
            uint64_t accessFlags = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));
            uint64_t codeOff = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));

            if (codeOff == 0) continue;
            (void)accessFlags;

            // Parse code_item for try/catch info
            if (static_cast<int>(codeOff) + 16 > static_cast<int>(totalSize)) continue;

            uint16_t triesSize = r16(&fileData[static_cast<size_t>(codeOff + 6)]);
            if (triesSize == 0) continue;

            uint32_t insnsSize = r32(&fileData[static_cast<size_t>(codeOff + 12)]);
            uint32_t tryItemsOffset = static_cast<uint32_t>(codeOff) + 16 + insnsSize * 2;

            // Align to 4 bytes
            tryItemsOffset = (tryItemsOffset + 3) & ~3U;
            if (tryItemsOffset + static_cast<uint32_t>(triesSize) * 8 > totalSize) continue;

            // Process try_items
            uint32_t handlersOffset = tryItemsOffset + triesSize * 8;
            if (handlersOffset + 1 > totalSize) continue;

            int handlerPos = static_cast<int>(handlersOffset);
            uint64_t handlersSize = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

            for (uint64_t hi = 0; hi < handlersSize; ++hi) {
                if (monitor && monitor->isCancelled()) break;
                if (handlerPos >= static_cast<int>(totalSize)) break;

                // Read encoded_catch_handler
                int64_t handlerSize = readSLEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));
                if (handlerPos >= static_cast<int>(totalSize)) break;

                uint64_t pairCount = static_cast<uint64_t>(handlerSize < 0 ? -handlerSize : handlerSize);
                bool hasCatchAll = (handlerSize <= 0);

                for (uint64_t pi = 0; pi < pairCount; ++pi) {
                    if (handlerPos + 1 > static_cast<int>(totalSize)) break;
                    uint64_t typeIdx = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));
                    uint64_t handlerAddr = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

                    Address handlerAddress(space, static_cast<int64_t>(handlerAddr));
                    if (memory->getBlock(handlerAddress)) {
                        // Look up type name from type_ids -> string_ids
                        std::string typeName;
                        if (typeIdx < totalSize / 4) {
                            uint32_t typeOff = r32(&fileData[static_cast<size_t>(typeIdsOff + typeIdx * 4)]);
                            if (typeOff < totalSize / 4) {
                                // typeOff is a string_id index
                                // string_id entry is uint32_t offset to string_data
                                // But typeOff might be a type_id index, not an offset
                                // Actually: type_id is: descriptor_idx (uint32)
                                // descriptor_idx is a string_id index
                                uint32_t strId = typeOff; // typeOff is descriptor_idx
                                if (strId * 4 + 4 <= totalSize) {
                                    uint32_t strOff = r32(&fileData[static_cast<size_t>(stringIdsOff + strId * 4)]);
                                    if (strOff < totalSize) {
                                        int strPos = static_cast<int>(strOff);
                                        // Skip uleb128 encoded length
                                        readULEB128(fileData.data(), strPos, static_cast<int>(totalSize));
                                        // Read string
                                        while (strPos < static_cast<int>(totalSize)) {
                                            char c = static_cast<char>(fileData[static_cast<size_t>(strPos++)]);
                                            if (c == '\0') break;
                                            typeName += c;
                                        }
                                    }
                                }
                            }
                        }

                        // Create a label at the handler address
                        std::string label = "EXC_" + (typeName.empty() ? std::to_string(typeIdx) : typeName);
                        if (!listing->getCodeUnitAt(handlerAddress) || listing->isUndefined(handlerAddress)) {
                            symTable->createLabel(handlerAddress, label, SourceType::ANALYSIS);
                        }

                        // Create reference from the DEX catch handler data to the handler address
                        // The reference is from the type_addr_pair uleb128 data area
                        // The handlerAddr was the last uleb128 we read, so the reference is
                        // from (handlerPos - encoded size of handlerAddr) to handlerAddress
                        // For simplicity, reference from a nearby fixed position
                        int refPos = handlerPos - 1; // approximate
                        if (refPos >= 0 && refPos < static_cast<int>(totalSize)) {
                            Address refAddr(space, static_cast<int64_t>(refPos));
                            refMgr->addMemoryReference(refAddr, handlerAddress,
                                                        &RefTypes::DATA, SourceType::ANALYSIS, -1);
                        }
                        ++totalHandlers;
                    }
                }

                if (hasCatchAll) {
                    if (handlerPos >= static_cast<int>(totalSize)) break;
                    uint64_t catchAllAddr = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

                    Address catchAllAddress(space, static_cast<int64_t>(catchAllAddr));
                    if (memory->getBlock(catchAllAddress)) {
                        std::string label = "EXC_catchall";
                        if (!listing->getCodeUnitAt(catchAllAddress) || listing->isUndefined(catchAllAddress)) {
                            symTable->createLabel(catchAllAddress, label, SourceType::ANALYSIS);
                        }
                        int refPos = handlerPos - 1;
                        if (refPos >= 0 && refPos < static_cast<int>(totalSize)) {
                            Address refAddr(space, static_cast<int64_t>(refPos));
                            refMgr->addMemoryReference(refAddr, catchAllAddress,
                                                        &RefTypes::DATA, SourceType::ANALYSIS, -1);
                        }
                        ++totalHandlers;
                    }
                }
            }

            // Also create labels for try_item addresses
            for (uint16_t ti = 0; ti < triesSize; ++ti) {
                uint32_t tryItemOff = tryItemsOffset + ti * 8;
                if (tryItemOff + 8 > totalSize) break;

                uint32_t tryStartAddr = r32(&fileData[static_cast<size_t>(tryItemOff)]);
                Address tryAddr(space, static_cast<int64_t>(tryStartAddr));

                if (memory->getBlock(tryAddr) && listing->isUndefined(tryAddr)) {
                    symTable->createLabel(tryAddr, "try_start_" + std::to_string(ti),
                                          SourceType::ANALYSIS);
                }
                ++totalTryItems;
            }
        }

        // Process virtual methods (same format)
        for (uint64_t mi = 0; mi < virtualMethodsSize; ++mi) {
            if (monitor && monitor->isCancelled()) break;
            if (pos >= static_cast<int>(totalSize)) break;

            readULEB128(fileData.data(), pos, static_cast<int>(totalSize)); // method_idx_diff
            uint64_t accessFlags = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));
            uint64_t codeOff = readULEB128(fileData.data(), pos, static_cast<int>(totalSize));

            if (codeOff == 0) continue;
            (void)accessFlags;

            if (static_cast<int>(codeOff) + 16 > static_cast<int>(totalSize)) continue;

            uint16_t triesSize = r16(&fileData[static_cast<size_t>(codeOff + 6)]);
            if (triesSize == 0) continue;

            uint32_t insnsSize = r32(&fileData[static_cast<size_t>(codeOff + 12)]);
            uint32_t tryItemsOffset = static_cast<uint32_t>(codeOff) + 16 + insnsSize * 2;
            tryItemsOffset = (tryItemsOffset + 3) & ~3U;
            if (tryItemsOffset + static_cast<uint32_t>(triesSize) * 8 > totalSize) continue;

            uint32_t handlersOffset = tryItemsOffset + triesSize * 8;
            if (handlersOffset + 1 > totalSize) continue;

            int handlerPos = static_cast<int>(handlersOffset);
            uint64_t handlersSize = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

            for (uint64_t hi = 0; hi < handlersSize; ++hi) {
                if (monitor && monitor->isCancelled()) break;
                if (handlerPos >= static_cast<int>(totalSize)) break;

                int64_t handlerSize = readSLEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));
                if (handlerPos >= static_cast<int>(totalSize)) break;

                uint64_t pairCount = static_cast<uint64_t>(handlerSize < 0 ? -handlerSize : handlerSize);
                bool hasCatchAll = (handlerSize <= 0);

                for (uint64_t pi = 0; pi < pairCount; ++pi) {
                    if (handlerPos + 1 > static_cast<int>(totalSize)) break;
                    uint64_t typeIdx = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));
                    uint64_t handlerAddr = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

                    Address handlerAddress(space, static_cast<int64_t>(handlerAddr));
                    if (memory->getBlock(handlerAddress)) {
                        std::string typeName;
                        if (typeIdx * 4 + 4 <= totalSize) {
                            uint32_t strId = r32(&fileData[static_cast<size_t>(typeIdsOff + typeIdx * 4)]);
                            if (strId * 4 + 4 <= totalSize) {
                                uint32_t strOff = r32(&fileData[static_cast<size_t>(stringIdsOff + strId * 4)]);
                                if (strOff < totalSize) {
                                    int strPos = static_cast<int>(strOff);
                                    readULEB128(fileData.data(), strPos, static_cast<int>(totalSize));
                                    while (strPos < static_cast<int>(totalSize)) {
                                        char c = static_cast<char>(fileData[static_cast<size_t>(strPos++)]);
                                        if (c == '\0') break;
                                        typeName += c;
                                    }
                                }
                            }
                        }

                        std::string label = "EXC_" + (typeName.empty() ? std::to_string(typeIdx) : typeName);
                        if (!listing->getCodeUnitAt(handlerAddress) || listing->isUndefined(handlerAddress)) {
                            symTable->createLabel(handlerAddress, label, SourceType::ANALYSIS);
                        }
                        ++totalHandlers;
                    }
                }

                if (hasCatchAll) {
                    if (handlerPos >= static_cast<int>(totalSize)) break;
                    uint64_t catchAllAddr = readULEB128(fileData.data(), handlerPos, static_cast<int>(totalSize));

                    Address catchAllAddress(space, static_cast<int64_t>(catchAllAddr));
                    if (memory->getBlock(catchAllAddress)) {
                        std::string label = "EXC_catchall";
                        if (!listing->getCodeUnitAt(catchAllAddress) || listing->isUndefined(catchAllAddress)) {
                            symTable->createLabel(catchAllAddress, label, SourceType::ANALYSIS);
                        }
                        ++totalHandlers;
                    }
                }
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(totalTryItems) +
                            " try items, " + std::to_string(totalHandlers) + " handlers");
    }

    if (totalTryItems > 0 || totalHandlers > 0) {
        Msg::info(getName(), "Discovered " + std::to_string(totalTryItems) +
                  " try blocks and " + std::to_string(totalHandlers) +
                  " exception handlers in DEX");
    }

    return true;
}

} // namespace ghidra
