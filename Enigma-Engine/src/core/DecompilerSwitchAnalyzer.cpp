#include <ghidra/DecompilerSwitchAnalyzer.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/DecompilerAdapter.h>
#include <ghidra/Listing.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SourceType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/RefType.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Msg.h>
#include <string>

namespace ghidra {

DecompilerSwitchAnalyzer::DecompilerSwitchAnalyzer()
    : AbstractAnalyzer("Decompiler Switch Analysis",
                       "Uses the decompiler to resolve indirect jumps and jump tables.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool DecompilerSwitchAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr && program->getLanguage() != nullptr && program->getLanguage()->supportsPcode();
}

bool DecompilerSwitchAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    if (!funcMgr) return false;

    // Create the C++ Decompiler Adapter
    auto adapter = createDecompilerAdapter();
    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!adapter || !programDB || !adapter->initialize(programDB)) {
        log.append("DecompilerSwitchAnalyzer: Failed to initialize decompiler adapter.");
        return false;
    }

    Memory* memory = program->getMemory();
    SymbolTable* symTable = program->getSymbolTable();
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!memory || !symTable) return true;

    auto iter = funcMgr->getFunctions(true);
    while (iter.hasNext()) {
        auto* func = iter.next();
        if (monitor && monitor->isCancelled()) break;

        std::vector<PcodeOutput> pcodeRes;
        adapter->generatePcode(func, pcodeRes);

        for (const auto& op : pcodeRes) {
            if (op.mnemonic != "BRANCHIND") continue;

            // The address input to BRANCHIND is the indirect jump target
            if (op.inputs.empty()) continue;
            uint64_t tableAddr = std::stoull(op.inputs[0], nullptr, 16);

            const AddressSpace* constSpace = program->getAddressFactory()->getDefaultAddressSpace();
            AddressSpace* space = const_cast<AddressSpace*>(constSpace);
            Address tableStart(space, static_cast<int64_t>(tableAddr));

            if (!memory->getBlock(tableStart)) continue;

            // Read potential table entries (4-byte entries is the common case)
            uint8_t buf[256];
            int read = memory->getBlock(tableStart)->getBytes(tableStart, buf, 256);
            if (read <= 0) continue;

            int entrySize = 4; // Default assumption for switch tables
            int entryCount = read / entrySize;
            int createdLabels = 0;

            for (int i = 0; i < entryCount && i < 64; ++i) {
                uint64_t entryVal = 0;
                int byteOff = i * entrySize;
                for (int j = 0; j < entrySize; ++j) {
                    entryVal |= static_cast<uint64_t>(buf[byteOff + j]) << (j * 8);
                }

                Address targetAddr(space, static_cast<int64_t>(entryVal));
                if (!memory->getBlock(targetAddr)) continue;
                if (program->getListing()->isUndefined(targetAddr)) continue;

                std::string label = func->getName() + "_switch_" + std::to_string(i);
                symTable->createLabel(targetAddr, label, SourceType::ANALYSIS);
                refMgr->addMemoryReference(func->getEntryPoint(), targetAddr,
                                           &RefTypes::DATA, SourceType::ANALYSIS, -1);
                ++createdLabels;
            }

            if (createdLabels > 0) {
                program->getBookmarkManager()->setBookmark(
                    func->getEntryPoint(), "ANALYSIS",
                    "Decompiler switch table: " + std::to_string(createdLabels) + " cases");
            }
        }
    }

    return true;
}

} // namespace ghidra
