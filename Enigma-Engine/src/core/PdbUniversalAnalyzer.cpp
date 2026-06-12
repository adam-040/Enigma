#include <ghidra/PdbUniversalAnalyzer.h>
#include <ghidra/PdbParser.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DataTypeManager.h>
#include <ghidra/DataTypeManagerImpl.h>
#include <ghidra/SignatureSource.h>
#include <ghidra/ParameterImpl.h>
#include <ghidra/VariableStorage.h>
#include <ghidra/SourceType.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSet.h>
#include <ghidra/DataOrganization.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>
#include <string>
#include <vector>
#include <fstream>
#include <unordered_map>

namespace ghidra {

namespace {
static const uint8_t RSDS_SIG[4] = {'R', 'S', 'D', 'S'};
static const uint8_t NB10_SIG[4] = {'N', 'B', '1', '0'};

static std::string extractPdbPath(Memory* memory) {
    for (auto* block : memory->getBlocks()) {
        std::string name = block->getName();
        if (name.find("debug") == std::string::npos && name.find(".rdata") == std::string::npos)
            continue;
        Address start = block->getStart();
        Address end = block->getEnd();
        int64_t size = end.getOffset() - start.getOffset() + 1;
        if (size > 4 * 1024 * 1024) size = 4 * 1024 * 1024;
        std::vector<uint8_t> buf(static_cast<size_t>(size));
        int read = block->getBytes(start, buf.data(), static_cast<int>(size));
        if (read <= 0) continue;

        for (int64_t i = 0; i < static_cast<int64_t>(read) - 24; ++i) {
            bool isRsds = true, isNb10 = true;
            for (int j = 0; j < 4; ++j) {
                if (buf[static_cast<size_t>(i + j)] != RSDS_SIG[j]) isRsds = false;
                if (buf[static_cast<size_t>(i + j)] != NB10_SIG[j]) isNb10 = false;
            }
            if (isRsds && i + 24 + 256 < read) {
                // RSDS: GUID (16) + age (4) + null-terminated path
                int64_t pathOff = i + 24;
                int64_t maxLen = std::min<int64_t>(256, read - pathOff);
                std::string path;
                for (int64_t j = pathOff; j < pathOff + maxLen && buf[static_cast<size_t>(j)] != 0; ++j)
                    path += static_cast<char>(buf[static_cast<size_t>(j)]);
                if (!path.empty()) return path;
            }
            if (isNb10 && i + 16 + 256 < read) {
                int64_t pathOff = i + 16;
                int64_t maxLen = std::min<int64_t>(256, read - pathOff);
                std::string path;
                for (int64_t j = pathOff; j < pathOff + maxLen && buf[static_cast<size_t>(j)] != 0; ++j)
                    path += static_cast<char>(buf[static_cast<size_t>(j)]);
                if (!path.empty()) return path;
            }
        }
    }
    return "";
}
} // anonymous namespace

PdbUniversalAnalyzer::PdbUniversalAnalyzer()
    : AbstractAnalyzer("PDB Universal",
                       "Loads PDB debug information using built-in PDB parser.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after().after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool PdbUniversalAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

bool PdbUniversalAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Loading PDB debug info...");

    Memory* memory = program->getMemory();
    if (!memory) return true;

    std::string pdbPath = extractPdbPath(memory);
    if (pdbPath.empty()) return true;

    Msg::info(getName(), "PDB file: " + pdbPath);

    // Try to find the PDB file on disk
    std::vector<std::string> searchPaths = {
        pdbPath,
        "./" + pdbPath,
    };
    // Extract just the filename for local directory search
    size_t lastSlash = pdbPath.find_last_of("/\\");
    if (lastSlash != std::string::npos)
        searchPaths.push_back(pdbPath.substr(lastSlash + 1));

    pdb::PdbFile pdb;
    bool opened = false;
    for (const auto& sp : searchPaths) {
        if (pdb.open(sp)) { opened = true; break; }
    }
    if (!opened) {
        Msg::info(getName(), "PDB file not found on disk: " + pdbPath);
        return true;
    }

    Msg::info(getName(), "PDB loaded: " + std::to_string(pdb.getHeader().blockSize) +
              " byte blocks, " + std::to_string(pdb.getHeader().numBlocks) + " blocks");

    program->getBookmarkManager()->setBookmark(
        program->getMinAddress(), "INFO", "PDB loaded: " + pdbPath);

    DataTypeManager* dtm = program->getDataTypeManager();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!funcMgr) return true;

    // Parse DBI stream (stream 3) for section contributions
    pdb::DbiInfo dbiInfo;
    std::map<uint32_t, uint64_t> sectionBases;
    pdb::PdbDbiReader dbiReader;
    dbiReader.parse(pdb, dbiInfo, sectionBases);

    // Parse TPI stream (stream 2) for type records
    pdb::PdbTypeReader typeReader;
    typeReader.parseTpi(pdb, 2);
    // IPI stream (stream 4) may contain additional types
    if (pdb.getStreamSize(4) > 0) typeReader.parseIpi(pdb, 4);

    // Parse module symbol streams from DBI
    pdb::PdbSymbolReader symReader;
    symReader.setSectionBases(sectionBases);

    // DBI stream contains module info: each module has a symbol stream index
    std::vector<uint8_t> dbiData;
    if (pdb.getStream(3, dbiData) && dbiData.size() > 64) {
        const uint8_t* d = dbiData.data();
        uint32_t moduleSize = d[24]|(d[25]<<8)|(d[26]<<16)|(d[27]<<24);
        uint32_t modPos = 64; // header size for DBI

        while (modPos + 8 < dbiData.size()) {
            uint32_t modStreamIdx = d[modPos]|(d[modPos+1]<<8)|(d[modPos+2]<<16)|(d[modPos+3]<<24);
            // section contribution for module mapping
            uint16_t section = d[modPos+12]|(d[modPos+13]<<8);
            if (modStreamIdx != 0xFFFFFFFF && modStreamIdx < 0xFFFF) {
                std::vector<uint8_t> modStream;
                if (pdb.getStream(modStreamIdx, modStream)) {
                    uint64_t secBase = 0;
                    auto sbIt = sectionBases.find(section);
                    if (sbIt != sectionBases.end()) secBase = sbIt->second;
                    symReader.parseModuleSymbols(pdb, modStream, secBase);
                }
            }
            uint32_t modInfoSize = moduleSize > 0 ? moduleSize : static_cast<uint32_t>(d[modPos+16]|d[modPos+17]|(d[modPos+18]<<16)|(d[modPos+19]<<24));
            if (modInfoSize == 0) break;
            modPos += modInfoSize;
            if (modPos >= dbiData.size() - 8) break;
        }
    }

    // Parse global/public symbol streams
    if (dbiInfo.globalStreamIdx != 0 && dbiInfo.globalStreamIdx != 0xFFFF)
        symReader.parseGlobalSymbols(pdb, dbiInfo.globalStreamIdx);
    if (dbiInfo.publicStreamIdx != 0 && dbiInfo.publicStreamIdx != 0xFFFF)
        symReader.parseGlobalSymbols(pdb, dbiInfo.publicStreamIdx);

    int funcsApplied = 0;

    // Create functions from PDB symbols
    for (const auto& sym : symReader.getFunctions()) {
        if (monitor->isCancelled()) break;
        uint64_t va = symReader.sectionToVA(sym.segment, sym.offset);
        if (va == 0) continue;

        Address entry(nullptr, static_cast<int64_t>(va));
        Function* func = funcMgr->getFunctionAt(entry);
        if (!func) {
            std::string fname = sym.name.empty() ? "pdb_func_" + std::to_string(va) : sym.name;
            func = funcMgr->createFunction(fname, entry, AddressSet(entry, entry), SourceType::ANALYSIS);
        }
        if (!func) continue;

        if (sym.typeIndex == 0) continue;

        // Resolve procedure type to get return type + parameters
        std::unordered_map<uint32_t, DataType*> typeCache;
        DataType* retDt = nullptr;
        auto* procType = typeReader.getType(sym.typeIndex);
        if (procType && procType->kind == pdb::PdbType::PROCEDURE) {
            retDt = typeReader.resolveType(procType->returnTypeId, dtm, typeCache);
            if (retDt) {
                func->setReturnType(retDt, SignatureSource::PDB);
                ++funcsApplied;
            }

            // Resolve parameter types from arglist
            auto* argList = typeReader.getType(procType->argListId);
            if (argList && argList->kind == pdb::PdbType::ARGLIST) {
                int paramOrdinal = 0;
                for (uint32_t paramTypeId : argList->memberTypeIds) {
                    DataType* paramDt = typeReader.resolveType(paramTypeId, dtm, typeCache);
                    if (!paramDt) paramDt = dtm->getDataType(CategoryPath::ROOT(), "byte");
                    std::string pname = "p" + std::to_string(paramOrdinal);
                    VariableStorage vs;
                    auto* param = new ParameterImpl(pname, paramOrdinal, paramDt, vs, program, SourceType::ANALYSIS);
                    func->addParameter(param, SignatureSource::PDB);
                    ++paramOrdinal; ++funcsApplied;
                }
            }
        }
    }

    Msg::info(getName(), "PDB: " + std::to_string(funcsApplied) + " types applied to " +
              std::to_string(static_cast<int>(symReader.getFunctions().size())) + " functions.");
    return true;
}

} // namespace ghidra
