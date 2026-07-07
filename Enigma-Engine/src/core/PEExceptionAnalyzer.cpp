#include <ghidra/PEExceptionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Listing.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/DataType.h>
#include <ghidra/DataTypeComponent.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/AutoNaming.h>
#include <ghidra/MessageLog.h>

#include <cstdint>
#include <string>

namespace ghidra {

// PE constants
static constexpr int IMAGE_NT_SIGNATURE = 0x00004550; // "PE\0\0"
static constexpr int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
static constexpr int IMAGE_SIZEOF_SHORT_NAME = 8;
static constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

static uint32_t read32(const uint8_t* buf, int off) {
    return (static_cast<uint32_t>(buf[off]) << 0) |
           (static_cast<uint32_t>(buf[off + 1]) << 8) |
           (static_cast<uint32_t>(buf[off + 2]) << 16) |
           (static_cast<uint32_t>(buf[off + 3]) << 24);
}

PEExceptionAnalyzer::PEExceptionAnalyzer()
    : AbstractAnalyzer("Windows x86 PE Exception Handling",
                       "Marks up exception handling data structures within a Visual Studio windows PE program.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool PEExceptionAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    const std::string& fmt = program->getExecutableFormat();
    return fmt.find("PE") != std::string::npos;
}

bool PEExceptionAnalyzer::added(Program* program, const AddressSetView& set,
                                 TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    DataTypeManager* dtm = program->getDataTypeManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !symTable || !listing || !dtm) return true;

    Address imageBase = program->getImageBase();

    // Read DOS header at imageBase: first 2 bytes = MZ magic
    // e_lfanew at offset 0x3C (4 bytes)
    uint8_t dosBuf[64];
    if (memory->getBytes(imageBase, dosBuf, 64) != 64) return true;

    uint32_t e_lfanew = read32(dosBuf, 0x3C);
    Address ntHeadersAddr = imageBase.add(e_lfanew);

    // Check NT signature
    uint8_t sigBuf[4];
    if (memory->getBytes(ntHeadersAddr, sigBuf, 4) != 4) return true;
    uint32_t signature = read32(sigBuf, 0);
    if (signature != IMAGE_NT_SIGNATURE) return true;

    // Determine PE32 vs PE32+: read header after signature
    uint8_t fileHeaderBuf[20];
    if (memory->getBytes(ntHeadersAddr.add(4), fileHeaderBuf, 20) != 20) return true;

    // File header at offset 4, SizeOfOptionalHeader at offset 16+2=18
    uint16_t sizeOfOptionalHeader = (static_cast<uint16_t>(fileHeaderBuf[14]) << 0) |
                                    (static_cast<uint16_t>(fileHeaderBuf[15]) << 8);

    // Optional header magic at ntHeaders + 4 + 20 = ntHeaders + 24
    uint8_t optMagicBuf[2];
    Address optionalHeaderAddr = ntHeadersAddr.add(24);
    if (memory->getBytes(optionalHeaderAddr, optMagicBuf, 2) != 2) return true;
    uint16_t optMagic = (static_cast<uint16_t>(optMagicBuf[0]) << 0) |
                        (static_cast<uint16_t>(optMagicBuf[1]) << 8);
    bool isPE32Plus = (optMagic == 0x020B);

    // Data directories start at:
    // PE32: optional header offset 96 (0x60)
    // PE32+: optional header offset 112 (0x70)
    int dataDirOffset = isPE32Plus ? 112 : 96;
    Address dataDirAddr = optionalHeaderAddr.add(dataDirOffset);

    // Read exception directory entry (index 3): {VirtualAddress, Size} (8 bytes each)
    Address exceptionDirAddr = dataDirAddr.add(IMAGE_DIRECTORY_ENTRY_EXCEPTION * 8);
    uint8_t dirBuf[8];
    if (memory->getBytes(exceptionDirAddr, dirBuf, 8) != 8) return true;

    uint32_t exceptionRVA = read32(dirBuf, 0);
    uint32_t exceptionSize = read32(dirBuf, 4);
    if (exceptionRVA == 0 || exceptionSize == 0) return true;

    Address funcTableAddr = imageBase.add(exceptionRVA);
    int entryCount = static_cast<int>(exceptionSize / 12); // each RUNTIME_FUNCTION is 12 bytes

    if (entryCount <= 0) return true;

    if (monitor) {
        monitor->setMessage(getName() + ": Processing " + std::to_string(entryCount) + " exception entries");
        monitor->initialize(entryCount);
    }

    // Create RUNTIME_FUNCTION structure type
    StructureDataType* rtFuncStruct = new StructureDataType("RUNTIME_FUNCTION", 12, dtm);
    rtFuncStruct->add(&DWordDataType::dataType(), 4, "BeginAddress", "");
    rtFuncStruct->add(&DWordDataType::dataType(), 4, "EndAddress", "");
    rtFuncStruct->add(&DWordDataType::dataType(), 4, "UnwindInfoAddress", "");
    DataType* resolvedStruct = dtm->resolve(rtFuncStruct, nullptr);

    for (int i = 0; i < entryCount; ++i) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(i);

        Address entryAddr = funcTableAddr.add(i * 12);
        uint8_t entryBuf[12];
        if (memory->getBytes(entryAddr, entryBuf, 12) != 12) continue;

        uint32_t beginRVA = read32(entryBuf, 0);
        uint32_t endRVA = read32(entryBuf, 4);
        uint32_t unwindRVA = read32(entryBuf, 8);

        // Apply RUNTIME_FUNCTION data type
        listing->createData(entryAddr, resolvedStruct, 12);

        Address beginAddr = imageBase.add(beginRVA);
        Address unwindAddr = imageBase.add(unwindRVA);

        // Create label at function start
        std::string funcName = AutoNaming::name("func", beginAddr);
        symTable->createLabel(beginAddr, funcName, SourceType::ANALYSIS);

        // Add references from the struct to the function and unwind info
        if (refMgr) {
            refMgr->addMemoryReference(entryAddr, beginAddr, &RefTypes::DATA,
                                        SourceType::ANALYSIS, 0);
            refMgr->addMemoryReference(entryAddr, imageBase.add(endRVA), &RefTypes::DATA,
                                        SourceType::ANALYSIS, 1);
            refMgr->addMemoryReference(entryAddr, unwindAddr, &RefTypes::DATA,
                                        SourceType::ANALYSIS, 2);
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Processed " + std::to_string(entryCount) + " exception entries");
    }

    return true;
}

} // namespace ghidra
