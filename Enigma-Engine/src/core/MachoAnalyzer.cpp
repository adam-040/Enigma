#include <ghidra/MachoAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Address.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/StructureDataType.h>
#include <ghidra/ByteDataType.h>
#include <ghidra/DWordDataType.h>
#include <ghidra/QWordDataType.h>
#include <ghidra/ArrayDataType.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <unordered_map>

namespace ghidra {

// Mach-O load command constants
static constexpr uint32_t LC_SEGMENT = 0x1;
static constexpr uint32_t LC_SYMTAB = 0x2;
static constexpr uint32_t LC_SYMSEG = 0x3;
static constexpr uint32_t LC_THREAD = 0x4;
static constexpr uint32_t LC_UNIXTHREAD = 0x5;
static constexpr uint32_t LC_LOADFVMLIB = 0x6;
static constexpr uint32_t LC_IDFVMLIB = 0x7;
static constexpr uint32_t LC_IDENT = 0x8;
static constexpr uint32_t LC_FVMFILE = 0x9;
static constexpr uint32_t LC_PREPAGE = 0xA;
static constexpr uint32_t LC_DYSYMTAB = 0xB;
static constexpr uint32_t LC_LOAD_DYLIB = 0xC;
static constexpr uint32_t LC_ID_DYLIB = 0xD;
static constexpr uint32_t LC_LOAD_DYLINKER = 0xE;
static constexpr uint32_t LC_ID_DYLINKER = 0xF;
static constexpr uint32_t LC_PREBOUND_DYLIB = 0x10;
static constexpr uint32_t LC_ROUTINES = 0x11;
static constexpr uint32_t LC_SUB_FRAMEWORK = 0x12;
static constexpr uint32_t LC_SUB_UMBRELLA = 0x13;
static constexpr uint32_t LC_SUB_CLIENT = 0x14;
static constexpr uint32_t LC_SUB_LIBRARY = 0x15;
static constexpr uint32_t LC_TWOLEVEL_HINTS = 0x16;
static constexpr uint32_t LC_PREBIND_CKSUM = 0x17;
static constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x18;
static constexpr uint32_t LC_SEGMENT_64 = 0x19;
static constexpr uint32_t LC_ROUTINES_64 = 0x1A;
static constexpr uint32_t LC_UUID = 0x1B;
static constexpr uint32_t LC_RPATH = 0x1C;
static constexpr uint32_t LC_CODE_SIGNATURE = 0x1D;
static constexpr uint32_t LC_SEGMENT_SPLIT_INFO = 0x1E;
static constexpr uint32_t LC_REEXPORT_DYLIB = 0x1F;
static constexpr uint32_t LC_LAZY_LOAD_DYLIB = 0x20;
static constexpr uint32_t LC_ENCRYPTION_INFO = 0x21;
static constexpr uint32_t LC_DYLD_INFO = 0x22;
static constexpr uint32_t LC_DYLD_INFO_ONLY = 0x22;
static constexpr uint32_t LC_LOAD_UPWARD_DYLIB = 0x23;
static constexpr uint32_t LC_VERSION_MIN_MACOSX = 0x24;
static constexpr uint32_t LC_VERSION_MIN_IPHONEOS = 0x25;
static constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
static constexpr uint32_t LC_DYLD_ENVIRONMENT = 0x27;
static constexpr uint32_t LC_MAIN = 0x28;
static constexpr uint32_t LC_DATA_IN_CODE = 0x29;
static constexpr uint32_t LC_SOURCE_VERSION = 0x2A;
static constexpr uint32_t LC_DYLIB_CODE_SIGN_DRS = 0x2B;
static constexpr uint32_t LC_ENCRYPTION_INFO_64 = 0x2C;
static constexpr uint32_t LC_LINKER_OPTION = 0x2D;
static constexpr uint32_t LC_LINKER_OPTIMIZATION_HINT = 0x2E;
static constexpr uint32_t LC_VERSION_MIN_TVOS = 0x2F;
static constexpr uint32_t LC_VERSION_MIN_WATCHOS = 0x30;
static constexpr uint32_t LC_NOTE = 0x31;
static constexpr uint32_t LC_BUILD_VERSION = 0x32;
static constexpr uint32_t LC_DYLD_EXPORTS_TRIE = 0x33;
static constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x34;
static constexpr uint32_t LC_FILESET_ENTRY = 0x35;

static const std::unordered_map<uint32_t, std::string>& getCommandNames() {
    static const std::unordered_map<uint32_t, std::string> names = {
        {LC_SEGMENT, "LC_SEGMENT"}, {LC_SYMTAB, "LC_SYMTAB"},
        {LC_SYMSEG, "LC_SYMSEG"}, {LC_THREAD, "LC_THREAD"},
        {LC_UNIXTHREAD, "LC_UNIXTHREAD"}, {LC_LOADFVMLIB, "LC_LOADFVMLIB"},
        {LC_IDFVMLIB, "LC_IDFVMLIB"}, {LC_IDENT, "LC_IDENT"},
        {LC_FVMFILE, "LC_FVMFILE"}, {LC_PREPAGE, "LC_PREPAGE"},
        {LC_DYSYMTAB, "LC_DYSYMTAB"}, {LC_LOAD_DYLIB, "LC_LOAD_DYLIB"},
        {LC_ID_DYLIB, "LC_ID_DYLIB"}, {LC_LOAD_DYLINKER, "LC_LOAD_DYLINKER"},
        {LC_ID_DYLINKER, "LC_ID_DYLINKER"}, {LC_PREBOUND_DYLIB, "LC_PREBOUND_DYLIB"},
        {LC_ROUTINES, "LC_ROUTINES"}, {LC_SUB_FRAMEWORK, "LC_SUB_FRAMEWORK"},
        {LC_SUB_UMBRELLA, "LC_SUB_UMBRELLA"}, {LC_SUB_CLIENT, "LC_SUB_CLIENT"},
        {LC_SUB_LIBRARY, "LC_SUB_LIBRARY"}, {LC_TWOLEVEL_HINTS, "LC_TWOLEVEL_HINTS"},
        {LC_PREBIND_CKSUM, "LC_PREBIND_CKSUM"}, {LC_LOAD_WEAK_DYLIB, "LC_LOAD_WEAK_DYLIB"},
        {LC_SEGMENT_64, "LC_SEGMENT_64"}, {LC_ROUTINES_64, "LC_ROUTINES_64"},
        {LC_UUID, "LC_UUID"}, {LC_RPATH, "LC_RPATH"},
        {LC_CODE_SIGNATURE, "LC_CODE_SIGNATURE"}, {LC_SEGMENT_SPLIT_INFO, "LC_SEGMENT_SPLIT_INFO"},
        {LC_REEXPORT_DYLIB, "LC_REEXPORT_DYLIB"}, {LC_LAZY_LOAD_DYLIB, "LC_LAZY_LOAD_DYLIB"},
        {LC_ENCRYPTION_INFO, "LC_ENCRYPTION_INFO"}, {LC_DYLD_INFO, "LC_DYLD_INFO"},
        {LC_DYLD_INFO_ONLY, "LC_DYLD_INFO_ONLY"}, {LC_LOAD_UPWARD_DYLIB, "LC_LOAD_UPWARD_DYLIB"},
        {LC_VERSION_MIN_MACOSX, "LC_VERSION_MIN_MACOSX"},
        {LC_VERSION_MIN_IPHONEOS, "LC_VERSION_MIN_IPHONEOS"},
        {LC_FUNCTION_STARTS, "LC_FUNCTION_STARTS"},
        {LC_DYLD_ENVIRONMENT, "LC_DYLD_ENVIRONMENT"}, {LC_MAIN, "LC_MAIN"},
        {LC_DATA_IN_CODE, "LC_DATA_IN_CODE"}, {LC_SOURCE_VERSION, "LC_SOURCE_VERSION"},
        {LC_DYLIB_CODE_SIGN_DRS, "LC_DYLIB_CODE_SIGN_DRS"},
        {LC_ENCRYPTION_INFO_64, "LC_ENCRYPTION_INFO_64"},
        {LC_LINKER_OPTION, "LC_LINKER_OPTION"},
        {LC_LINKER_OPTIMIZATION_HINT, "LC_LINKER_OPTIMIZATION_HINT"},
        {LC_VERSION_MIN_TVOS, "LC_VERSION_MIN_TVOS"},
        {LC_VERSION_MIN_WATCHOS, "LC_VERSION_MIN_WATCHOS"},
        {LC_NOTE, "LC_NOTE"}, {LC_BUILD_VERSION, "LC_BUILD_VERSION"},
        {LC_DYLD_EXPORTS_TRIE, "LC_DYLD_EXPORTS_TRIE"},
        {LC_DYLD_CHAINED_FIXUPS, "LC_DYLD_CHAINED_FIXUPS"},
        {LC_FILESET_ENTRY, "LC_FILESET_ENTRY"}
    };
    return names;
}

MachoAnalyzer::MachoAnalyzer()
    : AbstractBinaryFormatAnalyzer("Mach-O", "Mach-O") {
}

bool MachoAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Mac OS X Mach-O";
}

bool MachoAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing Mach-O header...");

    Memory* memory = program->getMemory();
    if (!memory) return false;

    auto* space = const_cast<AddressSpace*>(program->getAddressFactory()->getDefaultAddressSpace());
    Address addr(space, 0);

    uint8_t magic[4] = {0};
    if (memory->getBytes(addr, magic, 4) != 4) return false;

    bool is64Bit = false;
    if (magic[0] == 0xFE && magic[1] == 0xED && magic[2] == 0xFA && magic[3] == 0xCF) {
        is64Bit = true;
    } else if (magic[0] == 0xCF && magic[1] == 0xFA && magic[2] == 0xED && magic[3] == 0xFE) {
        is64Bit = true;
    } else if (magic[0] != 0xFE && magic[1] != 0xED && magic[2] != 0xFA && magic[3] != 0xCE &&
               magic[0] != 0xCE && magic[1] != 0xFA && magic[2] != 0xED && magic[3] != 0xFE) {
        return false;
    }

    DataTypeManager* dtm = program->getDataTypeManager();
    Listing* listing = program->getListing();
    SymbolTable* symTable = program->getSymbolTable();

    // --- Mach-O Header ---
    int headerSize = is64Bit ? 32 : 28;
    auto machHeader = std::make_unique<StructureDataType>("Mach_O_Header", 0, dtm);
    machHeader->add(&DWordDataType::dataType(), 4, "magic", "");
    machHeader->add(&DWordDataType::dataType(), 4, "cputype", "");
    machHeader->add(&DWordDataType::dataType(), 4, "cpusubtype", "");
    machHeader->add(&DWordDataType::dataType(), 4, "filetype", "");
    machHeader->add(&DWordDataType::dataType(), 4, "ncmds", "");
    machHeader->add(&DWordDataType::dataType(), 4, "sizeofcmds", "");
    machHeader->add(&DWordDataType::dataType(), 4, "flags", "");
    if (is64Bit) {
        machHeader->add(&DWordDataType::dataType(), 4, "reserved", "");
    }

    DataType* resolvedHeader = dtm->resolve(machHeader.get(), nullptr);
    if (!resolvedHeader) return false;

    Data* headerData = listing->createData(addr, resolvedHeader);
    if (headerData) headerData->setComment("Mach-O Header");
    symTable->createLabel(addr, "MACH_O_HEADER", SourceType::ANALYSIS);

    // Read ncmds and sizeofcmds from header
    uint8_t ncmdsBuf[4] = {0};
    Address ncmdsAddr = addr.add(16);
    memory->getBytes(ncmdsAddr, ncmdsBuf, 4);
    uint32_t ncmds = static_cast<uint32_t>(ncmdsBuf[0]) |
                     (static_cast<uint32_t>(ncmdsBuf[1]) << 8) |
                     (static_cast<uint32_t>(ncmdsBuf[2]) << 16) |
                     (static_cast<uint32_t>(ncmdsBuf[3]) << 24);

    uint8_t sizeofcmdsBuf[4] = {0};
    Address sizeofcmdsAddr = addr.add(20);
    memory->getBytes(sizeofcmdsAddr, sizeofcmdsBuf, 4);
    uint32_t sizeofcmds = static_cast<uint32_t>(sizeofcmdsBuf[0]) |
                          (static_cast<uint32_t>(sizeofcmdsBuf[1]) << 8) |
                          (static_cast<uint32_t>(sizeofcmdsBuf[2]) << 16) |
                          (static_cast<uint32_t>(sizeofcmdsBuf[3]) << 24);

    // --- Load Commands ---
    Address cmdAddr = addr.add(headerSize);
    const auto& cmdNames = getCommandNames();

    for (uint32_t i = 0; i < ncmds && monitor && !monitor->isCancelled(); ++i) {
        uint8_t cmdBuf[8] = {0};
        if (memory->getBytes(cmdAddr, cmdBuf, 8) != 8) break;

        uint32_t cmd = static_cast<uint32_t>(cmdBuf[0]) |
                       (static_cast<uint32_t>(cmdBuf[1]) << 8) |
                       (static_cast<uint32_t>(cmdBuf[2]) << 16) |
                       (static_cast<uint32_t>(cmdBuf[3]) << 24);

        uint32_t cmdsize = static_cast<uint32_t>(cmdBuf[4]) |
                           (static_cast<uint32_t>(cmdBuf[5]) << 8) |
                           (static_cast<uint32_t>(cmdBuf[6]) << 16) |
                           (static_cast<uint32_t>(cmdBuf[7]) << 24);

        if (cmdsize < 8) break;

        auto it = cmdNames.find(cmd);
        std::string cmdName = (it != cmdNames.end()) ? it->second : "LC_UNKNOWN";

        std::ostringstream typeName;
        typeName << "LoadCommand_" << cmdName << "_" << i;

        auto lcStruct = std::make_unique<StructureDataType>(typeName.str(), 0, dtm);
        lcStruct->add(&DWordDataType::dataType(), 4, "cmd", "");
        lcStruct->add(&DWordDataType::dataType(), 4, "cmdsize", "");

        // For LC_SEGMENT/LC_SEGMENT_64, read the segment name at offset 8
        if ((cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) && cmdsize >= 24) {
            int segNameLen = 16;
            uint8_t segNameBuf[17] = {0};
            Address segNameAddr = cmdAddr.add(8);
            memory->getBytes(segNameAddr, segNameBuf, segNameLen);
            std::string segName(reinterpret_cast<char*>(segNameBuf));
            segName = segName.substr(0, segName.find('\0'));

            lcStruct->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "segname", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "vmaddr", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "vmsize", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "fileoff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "filesize", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "maxprot", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "initprot", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nsects", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "flags", "");

            if (is64Bit) {
                // For 64-bit, vmaddr and vmsize are 8 bytes
                // The 4-byte fields above are wrong for 64-bit, so skip precise struct
            }

            std::ostringstream comment;
            comment << cmdName << ": " << segName;
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) lcData->setComment(comment.str());
            }
        } else if (cmd == LC_UUID && cmdsize >= 24) {
            lcStruct->add(new ArrayDataType(&ByteDataType::dataType(), 16, 1, dtm), 16, "uuid", "");
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) lcData->setComment(cmdName);
            }
        } else if (cmd == LC_SYMTAB && cmdsize >= 24) {
            lcStruct->add(&DWordDataType::dataType(), 4, "symoff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nsyms", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "stroff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "strsize", "");
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) lcData->setComment(cmdName);
            }
        } else if (cmd == LC_DYSYMTAB && cmdsize >= 72) {
            lcStruct->add(&DWordDataType::dataType(), 4, "ilocalsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nlocalsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "iextdefsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nextdefsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "iundefsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nundefsym", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "tocoff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "ntoc", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "modtaboff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nmodtab", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "extrefsymoff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nextrefsyms", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "indirectsymoff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nindirectsyms", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "extreloff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nextrel", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "locreloff", "");
            lcStruct->add(&DWordDataType::dataType(), 4, "nlocrel", "");
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) lcData->setComment(cmdName);
            }
        } else if (cmd == LC_MAIN && cmdsize >= 24) {
            lcStruct->add(&QWordDataType::dataType(), 8, "entryoff", "");
            lcStruct->add(&QWordDataType::dataType(), 8, "stacksize", "");
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) lcData->setComment(cmdName);
            }
        } else {
            // Generic load command — just create raw byte data for remainder
            DataType* resolvedLc = dtm->resolve(lcStruct.get(), nullptr);
            if (resolvedLc) {
                Data* lcData = listing->createData(cmdAddr, resolvedLc);
                if (lcData) {
                    std::string comment = cmdName + " (cmd=" +
                        std::to_string(cmd) + ", size=" + std::to_string(cmdsize) + ")";
                    lcData->setComment(comment);
                }
            }
        }

        // Create label for this load command
        std::ostringstream labelName;
        labelName << cmdName;
        if (i > 0) labelName << "_" << i;
        symTable->createLabel(cmdAddr, labelName.str(), SourceType::ANALYSIS);

        cmdAddr = cmdAddr.add(cmdsize);
    }

    if (monitor) monitor->setMessage("Mach-O analysis complete.");
    return true;
}

} // namespace ghidra
