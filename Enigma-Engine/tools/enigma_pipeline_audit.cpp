/// enigma_pipeline_audit.cpp
/// Comprehensive instrumented pipeline audit tool
/// Reports per-stage timing, function/instruction deltas, queue stats, decode failures

#include <ghidra/BinaryLoader.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/ExternalManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ProgramAddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/Analyzer.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/DataSectionFunctionScannerAnalyzer.h>
#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/MainRecognitionAnalyzer.h>
#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/FunctionDiscoveryAnalyzer.h>
#include <ghidra/DataRefFunctionAnalyzer.h>
#include <ghidra/PEExceptionAnalyzer.h>
#include <ghidra/ImportThunkAnalyzer.h>
#include <ghidra/FidAnalyzer.h>
#include <ghidra/ScalarOperandAnalyzer.h>
#include <ghidra/OperandReferenceAnalyzer.h>
#include <ghidra/DataOperandReferenceAnalyzer.h>
#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/StackReferenceAnalyzer.h>
#include <ghidra/StackVariableAnalyzer.h>
#include <ghidra/RelocationTable.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/AggressiveRecoveryAnalyzer.h>
#include <ghidra/FunctionBodyFinalizer.h>
#include <ghidra/AddressSet.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <memory>
#include <cstdlib>
#include <chrono>
#include <vector>
#include <map>
#include <algorithm>
#include <unordered_set>
#include <unordered_set>
#include <cstdio>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

using namespace ghidra;
using namespace std::chrono;

// ============================================================
// Per-analyzer timing record
// ============================================================
struct AnalyzerTiming {
    std::string name;
    double time_ms = 0;
    int funcs_before = 0;
    int funcs_after = 0;
    int instrs_before = 0;
    int instrs_after = 0;
    int refs_before = 0;
    int refs_after = 0;
    int data_before = 0;
    int data_after = 0;
    int exceptions = 0;
    bool executed = false;
    // Performance counter deltas
    int64_t getFunctionContaining_calls = 0;
    int64_t getFunctionAt_calls = 0;
    int64_t createFunction_calls = 0;
    int64_t getInstructionAt_calls = 0;
    int64_t getInstructionContaining_calls = 0;
    int64_t getDataAt_calls = 0;
    int64_t getDataContaining_calls = 0;
    int64_t addInstruction_calls = 0;
    // Warnings
    std::vector<std::string> warnings;
};

class InstrumentedMonitor : public StubTaskMonitor {
public:
    std::vector<AnalyzerTiming> analyzerTimings;
    Program* program = nullptr;
    std::unordered_set<std::string> knownAnalyzers;
    high_resolution_clock::time_point analyzerStartTime;
    FunctionManager::PerformanceCounters funcCountersBefore;
    Listing::PerformanceCounters listingCountersBefore;

    int getRefs() const {
        return program && program->getReferenceManager()
            ? (int)program->getReferenceManager()->getReferenceCount() : 0;
    }
    int getData() const {
        return program && program->getListing()
            ? (int)program->getListing()->getDataCount() : 0;
    }

    void setMessage(const std::string& msg) override {
        static const std::string prefix = "Running analyzer: ";
        std::string name;

        if (msg.size() > prefix.size() && msg.substr(0, prefix.size()) == prefix) {
            name = msg.substr(prefix.size());
        }

        if (!name.empty() && knownAnalyzers.count(name)) {
            if (!analyzerTimings.empty() && !analyzerTimings.back().executed) {
                endAnalyzer();
            }
            startAnalyzer(name);
        }

        StubTaskMonitor::setMessage(msg);
    }

    void startAnalyzer(const std::string& name) {
        analyzerStartTime = high_resolution_clock::now();
        AnalyzerTiming t;
        t.name = name;
        if (program) {
            auto* fm = program->getFunctionManager();
            auto* listing = program->getListing();
            t.funcs_before = fm ? fm->getFunctionCount() : 0;
            t.instrs_before = listing ? (int)listing->getInstructionCount() : 0;
            t.refs_before = getRefs();
            t.data_before = getData();
            // Snapshot performance counters before analyzer
            if (fm) funcCountersBefore = fm->getPerfCounters();
            if (listing) listingCountersBefore = listing->getPerfCounters();
        }
        analyzerTimings.push_back(t);
        std::cerr << "[START] " << name
                  << " funcs=" << t.funcs_before
                  << " instrs=" << t.instrs_before
                  << " refs=" << t.refs_before
                  << " data=" << t.data_before
                  << std::endl;
    }

    void endAnalyzer() {
        if (analyzerTimings.empty()) return;
        auto now = high_resolution_clock::now();
        auto& t = analyzerTimings.back();
        t.time_ms = duration<double, std::milli>(now - analyzerStartTime).count();
        if (program) {
            auto* fm = program->getFunctionManager();
            auto* listing = program->getListing();
            t.funcs_after = fm ? fm->getFunctionCount() : 0;
            t.instrs_after = listing ? (int)listing->getInstructionCount() : 0;
            t.refs_after = getRefs();
            t.data_after = getData();
            // Compute performance counter deltas
            if (fm) {
            auto& perf = fm->getPerfCounters();
            t.getFunctionContaining_calls = perf.getFunctionContaining_calls - funcCountersBefore.getFunctionContaining_calls;
            t.getFunctionAt_calls = perf.getFunctionAt_calls - funcCountersBefore.getFunctionAt_calls;
            t.createFunction_calls = perf.createFunction_calls - funcCountersBefore.createFunction_calls;
            // Reset for next analyzer
            fm->resetPerfCounters();
            }
            if (listing) {
            auto& perfL = listing->getPerfCounters();
            t.getInstructionAt_calls = perfL.getInstructionAt_calls - listingCountersBefore.getInstructionAt_calls;
            t.getInstructionContaining_calls = perfL.getInstructionContaining_calls - listingCountersBefore.getInstructionContaining_calls;
            t.getDataAt_calls = perfL.getDataAt_calls - listingCountersBefore.getDataAt_calls;
            t.getDataContaining_calls = perfL.getDataContaining_calls - listingCountersBefore.getDataContaining_calls;
            t.addInstruction_calls = perfL.addInstruction_calls - listingCountersBefore.addInstruction_calls;
            listing->resetPerfCounters();
            }
            // Warnings for large operations
            auto warnIf = [&](int64_t val, const char* desc) {
                if (val > 10000000) {
                    t.warnings.push_back(std::string(desc) + ": " + std::to_string(val) + " calls (>10M!)");
                }
            };
            warnIf(t.getFunctionContaining_calls, "getFunctionContaining");
            warnIf(t.getFunctionAt_calls, "getFunctionAt");
            warnIf(t.getInstructionContaining_calls, "getInstructionContaining");
            warnIf(t.getInstructionAt_calls, "getInstructionAt");
            warnIf(t.getDataContaining_calls, "getDataContaining");
        }
        t.executed = true;
        std::cerr << "[END] " << t.name
                  << " elapsed=" << std::fixed << std::setprecision(1) << t.time_ms << "ms"
                  << " funcsΔ=" << (t.funcs_after - t.funcs_before)
                  << " instrsΔ=" << (t.instrs_after - t.instrs_before)
                  << " refsΔ=" << (t.refs_after - t.refs_before)
                  << " dataΔ=" << (t.data_after - t.data_before)
                  << " getFuncContaining=" << t.getFunctionContaining_calls
                  << " getInstrContaining=" << t.getInstructionContaining_calls
                  << " getInstrAt=" << t.getInstructionAt_calls
                  << " getFuncAt=" << t.getFunctionAt_calls
                  << " addInstr=" << t.addInstruction_calls;
        if (!t.warnings.empty()) {
            for (auto& w : t.warnings) std::cerr << " [WARN] " << w;
        }
        std::cerr << std::endl;
    }
};

// ============================================================
// Pipeline stage timing helper
// ============================================================
struct StageTiming {
    std::string name;
    double time_ms;
    bool executed;
    int input_count;
    int output_count;
    std::string exception_msg;
};

std::vector<StageTiming> stageTimings;

void recordStage(const std::string& name, double time_ms, bool executed,
                 int input_count, int output_count, const std::string& exception_msg = "") {
    stageTimings.push_back({name, time_ms, executed, input_count, output_count, exception_msg});
}

// ============================================================
// Memory usage helper
// ============================================================
size_t getPeakMemoryKB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return pmc.PeakWorkingSetSize / 1024;
#endif
    return 0;
}

size_t getCurrentMemoryKB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
        return pmc.WorkingSetSize / 1024;
#endif
    return 0;
}

// ============================================================
// Helpers
// ============================================================
struct SectionStats {
    std::string name;
    uint64_t vaddr;
    uint64_t size;
    bool exec;
    bool read;
    bool write;
};

struct FunctionSourceStats {
    int total = 0;
    int from_pdata = 0;
    int from_calls = 0;
    int from_branches = 0;
    int from_exports = 0;
    int from_imports = 0;
    int from_functions = 0;
    int from_external_entries = 0;
};

struct QueueStats {
    int max_size = 0;
    int total_pushes = 0;
    int total_pops = 0;
    int duplicates_rejected = 0;
    bool drained_completely = false;
    int exceptions = 0;
};

struct DecodeFailure {
    uint64_t address;
    std::string reason;
    std::vector<uint8_t> context_bytes;
};

// ============================================================
// Main
// ============================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: enigma_pipeline_audit <binary> [options]\n";
        std::cerr << "Options:\n";
        std::cerr << "  --timeout N   Max seconds per analyzer (default: 60)\n";
        return 1;
    }

    std::string path = argv[1];
    int analyzerTimeout = 60;
    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--timeout" && i + 1 < argc) analyzerTimeout = atoi(argv[++i]);
    }

    std::string binName = path;
    auto pos = binName.find_last_of("/\\");
    if (pos != std::string::npos) binName = binName.substr(pos + 1);

    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, " ENIGMA PIPELINE AUDIT: %s\n", binName.c_str());
    fprintf(stderr, "========================================\n");

    auto t0 = high_resolution_clock::now();

    // ---- PHASE 1: Binary Loading ----
    fprintf(stderr, "\n[LOAD] Loading binary...\n");
    auto loadStart = high_resolution_clock::now();
    auto loader = createLoader();
    if (!loader) {
        std::cerr << "Failed to create loader\n";
        return 1;
    }
    if (!loader->load(path)) {
        std::cerr << "Failed to load: " << path << "\n";
        return 1;
    }
    auto loadEnd = high_resolution_clock::now();
    double loadTime = duration<double, std::milli>(loadEnd - loadStart).count();
    recordStage("BinaryLoader::load", loadTime, true, 0, 0);

    // Dump binary info
    std::string format = loader->getFormatName();
    std::string arch = loader->getArchitecture();
    int bitness = loader->getBitness();
    uint64_t imageBase = loader->getImageBase();
    uint64_t entryPoint = loader->getEntryPoint();
    bool bigEndian = loader->isBigEndian();

    std::cout << "\n=== BINARY INFO ===\n";
    std::cout << "Format: " << format << "\n";
    std::cout << "Arch: " << arch << "\n";
    std::cout << "Bitness: " << bitness << "\n";
    std::cout << "ImageBase: 0x" << std::hex << imageBase << std::dec << "\n";
    std::cout << "EntryPoint: 0x" << std::hex << entryPoint << std::dec << "\n";
    std::cout << "BigEndian: " << (bigEndian ? "yes" : "no") << "\n";

    // ---- Sections ----
    auto sections = loader->getSections();
    std::vector<SectionStats> sectionStats;
    uint64_t totalExecBytes = 0;
    uint64_t totalFileBytes = 0;
    std::cout << "\n=== SECTIONS (" << sections.size() << ") ===\n";
    for (auto& sec : sections) {
        std::cout << "  " << sec.name << ": 0x" << std::hex << sec.virtualAddress
                  << " - 0x" << (sec.virtualAddress + sec.virtualSize) << std::dec
                  << " size=" << sec.virtualSize << " file=" << sec.fileSize
                  << " r=" << sec.isReadable << " w=" << sec.isWritable << " x=" << sec.isExecutable
                  << "\n";
        sectionStats.push_back({sec.name, sec.virtualAddress, sec.virtualSize,
                                sec.isExecutable, sec.isReadable, sec.isWritable});
        totalFileBytes += sec.fileSize;
        if (sec.isExecutable) totalExecBytes += sec.virtualSize;
    }

    // ---- Imports/Exports/Symbols ----
    auto imports = loader->getImports();
    auto exports = loader->getExports();
    auto symbols = loader->getSymbols();
    int funcSyms = 0;
    for (auto& s : symbols) if (s.isFunction) funcSyms++;
    int extSyms = 0;
    for (auto& s : symbols) if (s.isExternal) extSyms++;

    std::cout << "\n=== SYMBOLS ===\n";
    std::cout << "Imports: " << imports.size() << "\n";
    std::cout << "Exports: " << exports.size() << "\n";
    std::cout << "Symbols: " << symbols.size() << " (functions: " << funcSyms << ", external: " << extSyms << ")\n";

    // List imports
    std::cout << "\nImports:\n";
    for (auto& imp : imports) {
        std::cout << "  " << imp.libraryName << "!" << imp.functionName
                  << " @ 0x" << std::hex << imp.address << std::dec << "\n";
    }

    // List exports
    std::cout << "\nExports:\n";
    for (auto& exp : exports) {
        std::cout << "  " << exp.name << " @ 0x" << std::hex << exp.address << std::dec << "\n";
    }

    // ---- PHASE 2: Program Creation ----
    fprintf(stderr, "\n[PROGRAM] Creating program...\n");
    auto progStart = high_resolution_clock::now();

    auto* ramSpace = new GenericAddressSpace("ram", 64, AddressSpace::TYPE_RAM, 1);
    auto* constSpace = new GenericAddressSpace("const", 64, AddressSpace::TYPE_CONSTANT, 2);
    auto* uniqueSpace = new GenericAddressSpace("unique", 64, AddressSpace::TYPE_UNIQUE, 3);
    auto* regSpace = new GenericAddressSpace("register", 64, AddressSpace::TYPE_REGISTER, 4);
    auto* stackSpace = new GenericAddressSpace("stack", 64, AddressSpace::TYPE_STACK, 5);

    auto prog = std::make_unique<ProgramDB>("audit", nullptr, nullptr);
    auto* addrFactory = dynamic_cast<ProgramAddressFactory*>(prog->getAddressFactory());
    if (addrFactory) {
        addrFactory->addAddressSpace(ramSpace);
        addrFactory->addAddressSpace(constSpace);
        addrFactory->addAddressSpace(uniqueSpace);
        addrFactory->addAddressSpace(regSpace);
        addrFactory->addAddressSpace(stackSpace);
        addrFactory->setDefaultSpace(ramSpace);
    }

    auto progCreateEnd = high_resolution_clock::now();
    recordStage("Program creation", duration<double, std::milli>(progCreateEnd - progStart).count(), true, 0, 0);

    // ---- PHASE 3: Populate Program ----
    fprintf(stderr, "\n[POPULATE] populateProgram()...\n");
    auto popStart = high_resolution_clock::now();
    bool popOk = loader->populateProgram(prog.get());
    auto popEnd = high_resolution_clock::now();
    double popTime = duration<double, std::milli>(popEnd - popStart).count();

    if (!popOk) {
        std::cerr << "populateProgram failed\n";
        return 1;
    }
    recordStage("populateProgram", popTime, true, (int)sections.size(),
                prog->getFunctionManager() ? prog->getFunctionManager()->getFunctionCount() : 0);

    // Post-populate state
    auto* fm = prog->getFunctionManager();
    auto* listing = prog->getListing();
    auto* symTable = prog->getSymbolTable();
    auto* extMgr = prog->getExternalManager();
    auto* mem = prog->getMemory();
    auto* refMgr = prog->getReferenceManager();

    int initialFuncs = fm ? fm->getFunctionCount() : 0;
    int initialInstrs = listing ? (int)listing->getInstructionCount() : 0;
    int initialSyms = symTable ? symTable->getNumSymbols() : 0;
    int initialExtLocs = extMgr ? (int)extMgr->getExternalLocationCount() : 0;
    int initialExtEntries = symTable ? (int)symTable->getExternalEntryPoints().size() : 0;
    int initialRefs = refMgr ? (int)refMgr->getReferenceCount() : 0;

    std::cout << "\n=== AFTER POPULATEPROGRAM ===\n";
    std::cout << "Functions: " << initialFuncs << "\n";
    std::cout << "Instructions: " << initialInstrs << "\n";
    std::cout << "Data: " << (listing ? (int)listing->getDataCount() : 0) << "\n";
    std::cout << "Symbols: " << initialSyms << "\n";
    std::cout << "External Locations: " << initialExtLocs << "\n";
    std::cout << "External Entry Points: " << initialExtEntries << "\n";
    std::cout << "References: " << initialRefs << "\n";

    // Dump pre-existing functions
    if (fm) {
        auto fit = fm->getFunctions(true);
        int i = 0;
        while (fit.hasNext() && i < 100) {
            auto* f = fit.next();
            if (f) {
                std::cout << "  FUNC[" << i << "] 0x" << std::hex
                          << f->getEntryPoint().getOffset() << std::dec
                          << " '" << f->getName() << "'"
                          << " thunk=" << f->isThunk()
                          << " external=" << f->isExternal()
                          << "\n";
                i++;
            }
        }
        std::cout << "  (" << fm->getFunctionCount() << " total, " << i << " shown)\n";
    }

    // Memory blocks
    if (mem) {
        auto blocks = mem->getBlocks();
        std::cout << "\n=== MEMORY BLOCKS (" << blocks.size() << ") ===\n";
        for (auto* blk : blocks) {
            std::cout << "  " << blk->getName() << ": 0x" << std::hex
                      << blk->getStart().getOffset() << " - 0x"
                      << blk->getEnd().getOffset() << std::dec
                      << " size=" << (blk->getEnd().getOffset() - blk->getStart().getOffset() + 1)
                      << " r=" << blk->isRead() << " w=" << blk->isWrite() << " x=" << blk->isExecute()
                      << "\n";
        }
    }

    // Get external entry points
    auto extEntryPoints = symTable ? symTable->getExternalEntryPoints() : std::vector<Address>();
    std::cout << "\n=== EXTERNAL ENTRY POINTS (" << extEntryPoints.size() << ") ===\n";
    for (size_t i = 0; i < extEntryPoints.size() && i < 20; i++) {
        std::cout << "  [" << i << "] 0x" << std::hex << extEntryPoints[i].getOffset() << std::dec << "\n";
    }
    if (extEntryPoints.size() > 20) std::cout << "  ... (" << (extEntryPoints.size() - 20) << " more)\n";

    // ---- FunctionDiscoveryAnalyzer: creates functions from loader metadata (imports, exports, etc.) ----
    {
        FunctionDiscoveryOptions fdOpts;
        fdOpts.includeExternalInFunctionManager = true;
        FunctionDiscoveryAnalyzer fdAnalyzer(fdOpts);
        fdAnalyzer.analyzeLoader(*loader);
        if (fm && ramSpace) {
            auto fdResult = fdAnalyzer.applyTo(*fm, ramSpace);
            std::cout << "\n=== FUNCTION DISCOVERY ANALYZER ===\n";
            std::cout << "  Created: " << fdResult.createdFunctions << " functions\n";
            std::cout << "  Skipped (existing): " << fdResult.skippedExisting << "\n";
            std::cout << "  Skipped (external): " << fdResult.skippedExternal << "\n";
            std::cout << "  Failed: " << fdResult.failedCreates << "\n";
            std::cout << "  Candidates: " << fdResult.candidates.size() << "\n";
            auto* pfm = prog->getFunctionManager();
            std::cout << "  Total functions after: " << (pfm ? pfm->getFunctionCount() : -1) << "\n";
        }
    }

    // ---- PHASE 4: Analysis Pipeline ----
    fprintf(stderr, "\n[ANALYSIS] Creating analysis manager...\n");
    auto analysisMgr = std::make_unique<AutoAnalysisManager>(prog.get());

    // Register analyzers
    struct AnalyzerRegistration {
        std::string name;
        std::unique_ptr<Analyzer> (*factory)();
        bool registered = false;
    };

    auto registerAnalyzer = [&](const std::string& name, auto factory) {
        analysisMgr->registerAnalyzer(std::move(factory()));
        fprintf(stderr, "  Registered: %s\n", name.c_str());
    };

    // Register all analyzers that matter for function discovery
    // Order must match enigma_dump_functions.cpp for comparable timing
    registerAnalyzer("EntryPointAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<EntryPointAnalyzer>(); });
    registerAnalyzer("DisassemblyAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<DisassemblyAnalyzer>(); });
    registerAnalyzer("FunctionStartAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FunctionStartAnalyzer>(); });
    registerAnalyzer("DataSectionFunctionScannerAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<DataSectionFunctionScannerAnalyzer>(); });
    registerAnalyzer("FunctionStartDataPostAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FunctionStartDataPostAnalyzer>(); });
    registerAnalyzer("FunctionStartFuncAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FunctionStartFuncAnalyzer>(); });
    registerAnalyzer("ApplyDataArchiveAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ApplyDataArchiveAnalyzer>(); });
    registerAnalyzer("ExternalEntryFunctionAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ExternalEntryFunctionAnalyzer>(); });
    registerAnalyzer("PEExceptionAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ghidra::PEExceptionAnalyzer>(); });
    registerAnalyzer("DataRefFunctionAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<DataRefFunctionAnalyzer>(); });
    registerAnalyzer("ScalarOperandAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ScalarOperandAnalyzer>(); });
    registerAnalyzer("OperandReferenceAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<OperandReferenceAnalyzer>(); });
    registerAnalyzer("DataOperandReferenceAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<DataOperandReferenceAnalyzer>(); });
    registerAnalyzer("ConstantPropagationAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ConstantPropagationAnalyzer>(); });
    registerAnalyzer("StackReferenceAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<StackReferenceAnalyzer>(); });
    registerAnalyzer("StackVariableAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<StackVariableAnalyzer>(); });
    registerAnalyzer("FragmentMergeAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FragmentMergeAnalyzer>(); });
    registerAnalyzer("ImportThunkAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<ImportThunkAnalyzer>(); });
    registerAnalyzer("MainRecognitionAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<MainRecognitionAnalyzer>(); });
    registerAnalyzer("FidAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FidAnalyzer>(); });
    // Phase B: Aggressive recovery — disabled by default
    registerAnalyzer("FunctionBodyFinalizer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<FunctionBodyFinalizer>(); });
    registerAnalyzer("AggressiveRecoveryAnalyzer", []() -> std::unique_ptr<Analyzer> { return std::make_unique<AggressiveRecoveryAnalyzer>(); });

    std::vector<Analyzer*> allAnalyzers = analysisMgr->getAnalyzers();
    std::cout << "\n=== REGISTERED ANALYZERS (" << allAnalyzers.size() << ") ===\n";
    for (auto* a : allAnalyzers) {
        std::cout << "  " << a->getName() << " (type=" << analyzerTypeName(a->getAnalysisType())
                  << ", priority=" << a->getPriority().priority() << ")\n";
    }

    // Pre-analysis snapshot
    std::cout << "\n=== BEFORE ANALYSIS ===\n";
    std::cout << "  Functions: " << (fm ? fm->getFunctionCount() : -1) << "\n";
    std::cout << "  Instructions: " << (listing ? listing->getInstructionCount() : -1) << "\n";
    std::cout << "  Data: " << (listing ? listing->getDataCount() : -1) << "\n";
    std::cout << "  References: " << (refMgr ? refMgr->getReferenceCount() : -1) << "\n";

    // ---- Run Analysis ----
    fprintf(stderr, "\n[ANALYSIS] Running analysis pipeline...\n");
    auto analysisStart = high_resolution_clock::now();

    std::vector<AnalyzerTiming> analyzerTimings;

    // Build set of known analyzer names for the monitor
    InstrumentedMonitor instMonitor;
    instMonitor.program = prog.get();
    for (auto* a : allAnalyzers) {
        instMonitor.knownAnalyzers.insert(a->getName());
    }

    fprintf(stderr, "  Running full analysis pipeline...\n");
    try {
        analysisMgr->analyze(&instMonitor);
    } catch (const std::exception& e) {
        std::cerr << "\n[ANALYSIS] EXCEPTION during analysis: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "\n[ANALYSIS] Unknown exception during analysis\n";
    }
    instMonitor.endAnalyzer(); // flush last analyzer

    for (auto& t : instMonitor.analyzerTimings) {
        analyzerTimings.push_back(std::move(t));
    }

    auto analysisEnd = high_resolution_clock::now();
    double analysisTime = duration<double, std::milli>(analysisEnd - analysisStart).count();
    recordStage("Full Analysis Pipeline", analysisTime, true, 0, 0);

    // ---- Post-Analysis State ----
    int finalFuncs = fm ? fm->getFunctionCount() : 0;
    int finalInstrs = listing ? (int)listing->getInstructionCount() : 0;
    int finalData = listing ? (int)listing->getDataCount() : 0;
    int finalRefs = refMgr ? (int)refMgr->getReferenceCount() : 0;

    std::cout << "\n=== AFTER ANALYSIS ===\n";
    std::cout << "  Functions: " << finalFuncs << "\n";
    std::cout << "  Instructions: " << finalInstrs << "\n";
    std::cout << "  Data: " << finalData << "\n";
    std::cout << "  References: " << finalRefs << "\n";

    // ---- PHASE 6: Per-Analyzer Timing Report ----
    std::cout << "\n========================================\n";
    std::cout << " PER-ANALYZER TIMING & DELTAS\n";
    std::cout << "========================================\n";
    std::cout.setf(std::ios::fixed, std::ios::floatfield);
    std::cout.precision(1);

    std::cout << "\n  " << "Analyzer" << "\t\t" << "Time(ms)" << "\t" << "FuncsΔ" << "\t" << "InstrsΔ" << "\t" << "Exec?" << "\t" << "Exceptions\n";
    std::cout << "  " << std::string(70, '-') << "\n";

    int prevFuncs = initialFuncs;
    int prevInstrs = initialInstrs;
    int totalTimedMs = 0;
    for (auto& t : analyzerTimings) {
        int fDelta = t.funcs_after - t.funcs_before;
        int iDelta = t.instrs_after - t.instrs_before;
        std::string name = t.name.length() > 25 ? t.name.substr(0, 22) + "..." : t.name;
        std::cout << "  " << name << "\t"
                  << t.time_ms << "\t"
                  << (fDelta >= 0 ? "+" : "") << fDelta << "\t"
                  << (iDelta >= 0 ? "+" : "") << iDelta << "\t"
                  << (t.executed ? "Y" : "N") << "\t"
                  << t.exceptions << "\n";
        totalTimedMs += (int)t.time_ms;
        prevFuncs = t.funcs_after;
        prevInstrs = t.instrs_after;
    }

    std::cout << "  " << std::string(70, '-') << "\n";
    std::cout << "  Total timed: " << totalTimedMs << " ms\n";
    std::cout << "  Total wall: " << (long)analysisTime << " ms\n";
    std::cout << "  Untimed overhead: " << (long)(analysisTime - totalTimedMs) << " ms\n";

    // ---- RANKED PERFORMANCE REPORT ----
    std::cout << "\n========================================\n";
    std::cout << " RANKED ANALYZER PERFORMANCE (by runtime)\n";
    std::cout << "========================================\n";

    // Sort by time descending
    std::vector<AnalyzerTiming*> sorted;
    double totalOpsTime = 0;
    for (auto& t : analyzerTimings) { sorted.push_back(&t); totalOpsTime += t.time_ms; }
    std::sort(sorted.begin(), sorted.end(), [](AnalyzerTiming* a, AnalyzerTiming* b) {
        return a->time_ms > b->time_ms;
    });

    std::cout << "\n  Rank | Analyzer                      | Time(ms)  | %Total | FuncsΔ | InstrsΔ | RefsΔ | DataΔ | Operations                         | Complexity\n";
    std::cout << "  " << std::string(120, '-') << "\n";
    for (size_t ri = 0; ri < sorted.size(); ri++) {
        auto* t = sorted[ri];
        if (!t->executed) continue;
        double pct = totalOpsTime > 0 ? (t->time_ms / totalOpsTime) * 100.0 : 0.0;
        int fDelta = t->funcs_after - t->funcs_before;
        int iDelta = t->instrs_after - t->instrs_before;
        int rDelta = t->refs_after - t->refs_before;
        int dDelta = t->data_after - t->data_before;

        // Build operations summary
        std::string ops;
        auto addOp = [&](int64_t cnt, const char* label) {
            if (cnt > 0) {
                if (!ops.empty()) ops += ", ";
                ops += std::to_string(cnt) + " " + label;
            }
        };
        addOp(t->getFunctionContaining_calls, "getFuncContaining");
        addOp(t->getFunctionAt_calls, "getFuncAt");
        addOp(t->createFunction_calls, "createFunc");
        addOp(t->getInstructionContaining_calls, "getInstrContaining");
        addOp(t->getInstructionAt_calls, "getInstrAt");
        addOp(t->getDataContaining_calls, "getDataContaining");
        addOp(t->getDataAt_calls, "getDataAt");
        addOp(t->addInstruction_calls, "addInstr");

        // Estimate complexity
        std::string complexity;
        int64_t totalCalls = t->getFunctionContaining_calls + t->getFunctionAt_calls +
            t->getInstructionContaining_calls + t->getInstructionAt_calls +
            t->getDataContaining_calls + t->getDataAt_calls;
        if (totalCalls > 10000000) complexity = "O(N?) >10M API calls!";
        else if (t->getInstructionContaining_calls > 1000000) complexity = "O(N) on instrs";
        else if (t->getFunctionContaining_calls > 1000000) complexity = "O(N) on funcs";
        else complexity = "O(1) or O(N) small";

        std::string name = t->name.length() > 30 ? t->name.substr(0, 27) + "..." : t->name;
        std::cout << "  " << (ri+1) << "    | "
                  << std::left << std::setw(30) << name << std::right << " | "
                  << std::setw(9) << std::fixed << std::setprecision(1) << t->time_ms << " | "
                  << std::setw(6) << std::fixed << std::setprecision(1) << pct << "% | "
                  << std::setw(5) << (fDelta >= 0 ? "+" : "") << fDelta << "  | "
                  << std::setw(6) << (iDelta >= 0 ? "+" : "") << iDelta << "  | "
                  << std::setw(5) << (rDelta >= 0 ? "+" : "") << rDelta << "  | "
                  << std::setw(5) << (dDelta >= 0 ? "+" : "") << dDelta << "  | "
                  << std::left << std::setw(35) << ops << std::right << " | "
                  << complexity << "\n";

        // Print any warnings for this analyzer
        for (auto& w : t->warnings) {
            std::cout << "  *** WARNING: " << w << "\n";
        }
    }
    std::cout << "  " << std::string(120, '-') << "\n";

    // Bottleneck summary
    std::cout << "\n=== BOTTLENECK ANALYSIS ===\n";
    if (!sorted.empty() && sorted[0]->executed) {
        auto* t = sorted[0];
        double pct = totalOpsTime > 0 ? (t->time_ms / totalOpsTime) * 100.0 : 0.0;
        int64_t totalCalls = t->getFunctionContaining_calls + t->getFunctionAt_calls +
            t->getInstructionContaining_calls + t->getInstructionAt_calls +
            t->getDataContaining_calls + t->getDataAt_calls;
        std::cout << "  Slowest analyzer: " << t->name << " (" << pct << "% of runtime)\n";
        std::cout << "  Runtime: " << t->time_ms << " ms\n";
        std::cout << "  Total API calls: " << totalCalls << "\n";
        if (t->getInstructionContaining_calls > 1000000)
            std::cout << "  *** EVIDENCE: " << t->getInstructionContaining_calls
                      << " getInstructionContaining() calls - O(N) linear scan over "
                      << t->instrs_after << " instructions\n";
        if (t->getFunctionContaining_calls > 1000000)
            std::cout << "  *** EVIDENCE: " << t->getFunctionContaining_calls
                      << " getFunctionContaining() calls\n";
        if (t->warnings.size() > 0)
            std::cout << "  *** PATHOLOGICAL: " << t->warnings.size() << " warnings issued\n";
    }
    if (sorted.size() >= 2 && sorted[1]->executed) {
        auto* t = sorted[1];
        double pct = totalOpsTime > 0 ? (t->time_ms / totalOpsTime) * 100.0 : 0.0;
        std::cout << "  2nd slowest: " << t->name << " (" << pct << "%)\n";
    }

    // ---- PHASE 6: Performance ----
    std::cout << "\n========================================\n";
    std::cout << " PERFORMANCE\n";
    std::cout << "========================================\n";
    auto totalElapsed = duration<double, std::milli>(high_resolution_clock::now() - t0).count();
    std::cout << "  Binary load time: " << loadTime << " ms\n";
    std::cout << "  Program creation: " << duration<double, std::milli>(progCreateEnd - progStart).count() << " ms\n";
    std::cout << "  populateProgram: " << popTime << " ms\n";
    std::cout << "  Analysis time: " << analysisTime << " ms\n";
    std::cout << "  Total time: " << totalElapsed << " ms\n";
    std::cout << "  Peak memory: " << getPeakMemoryKB() << " KB\n";
    std::cout << "  Current memory: " << getCurrentMemoryKB() << " KB\n";

    // ---- COVERAGE ----
    std::cout << "\n========================================\n";
    std::cout << " COVERAGE\n";
    std::cout << "========================================\n";
    std::cout << "  Executable bytes: " << totalExecBytes << "\n";
    std::cout << "  Instructions: " << finalInstrs << "\n";
    std::cout << "  Functions: " << finalFuncs << "\n";
    std::cout << "  Data items: " << finalData << "\n";
    std::cout << "  References: " << finalRefs << "\n";

    // Average instruction size from x86-64 (typical ~3 bytes)
    // But we can compute actual coverage from instruction addresses in listing
    double coveragePct = totalExecBytes > 0 ?
        (double)finalInstrs * 4.0 / (double)totalExecBytes * 100.0 : 0.0;
    std::cout << "  Est. code coverage (instrs*4 / exec_bytes): " << coveragePct << "%\n";

    // ---- EXTERNAL ENTRIES ----
    std::cout << "\n========================================\n";
    std::cout << " EXTERNAL ENTRY POINTS (pdata/export)\n";
    std::cout << "========================================\n";
    int finalExtEntries = symTable ? (int)symTable->getExternalEntryPoints().size() : 0;
    std::cout << "  External Entry Points: " << finalExtEntries << "\n";

    // ---- THUNKS / EXTERNALS ----
    if (fm) {
        int thunkCount = 0;
        int extFuncCount = 0;
        auto fit = fm->getFunctions(true);
        while (fit.hasNext()) {
            auto* f = fit.next();
            if (f->isThunk()) thunkCount++;
            if (f->isExternal()) extFuncCount++;
        }
        std::cout << "\n=== SPECIAL FUNCTIONS ===\n";
        std::cout << "  Thunk functions: " << thunkCount << "\n";
        std::cout << "  External functions: " << extFuncCount << "\n";
    }

    // ---- Full function list ----
    if (fm) {
        std::cout << "\n=== ALL FUNCTIONS (" << finalFuncs << ") ===\n";
        auto fit = fm->getFunctions(true);
        int i = 0;
        while (fit.hasNext() && i < finalFuncs) {
            auto* f = fit.next();
            if (f) {
                std::cout << "  FUNC[" << i << "] 0x" << std::hex
                          << f->getEntryPoint().getOffset() << std::dec
                          << " '" << f->getName() << "'"
                          << " thunk=" << f->isThunk()
                          << " ext=" << f->isExternal()
                          << "\n";
                i++;
            }
        }
    }

    // ---- STAGE TIMING SUMMARY ----
    std::cout << "\n========================================\n";
    std::cout << " STAGE TIMING SUMMARY\n";
    std::cout << "========================================\n";
    std::cout << "  " << "Stage" << "\t\t" << "Time(ms)" << "\t" << "Exec?" << "\t" << "Input" << "\t" << "Output\n";
    std::cout << "  " << std::string(60, '-') << "\n";
    for (auto& s : stageTimings) {
        std::cout << "  " << s.name << "\t\t"
                  << s.time_ms << "\t"
                  << (s.executed ? "Y" : "N") << "\t"
                  << s.input_count << "\t"
                  << s.output_count << "\n";
    }

    // ---- FUNCTION DENSITY ----
    std::cout << "\n========================================\n";
    std::cout << " FUNCTION DENSITY\n";
    std::cout << "========================================\n";
    if (totalExecBytes > 0) {
        double funcsPerMB = (double)finalFuncs / ((double)totalExecBytes / 1048576.0);
        std::cout << "  Functions per MB of executable code: " << funcsPerMB << "\n";
    }
    if (finalFuncs > 0) {
        double instrsPerFunc = (double)finalInstrs / (double)finalFuncs;
        std::cout << "  Avg instructions per function: " << instrsPerFunc << "\n";
    }

    // ---- FINAL SUMMARY ----
    std::cout << "\n========================================\n";
    std::cout << " PIPELINE AUDIT COMPLETE: " << binName << "\n";
    std::cout << "========================================\n";
    std::cout << "  Functions: " << initialFuncs << " -> " << finalFuncs << " (+" << (finalFuncs - initialFuncs) << ")\n";
    std::cout << "  Instructions: " << initialInstrs << " -> " << finalInstrs << " (+" << (finalInstrs - initialInstrs) << ")\n";
    std::cout << "  Data: " << finalData << "\n";
    std::cout << "  Total time: " << (long)totalElapsed << " ms\n";
    std::cout << "  Peak memory: " << getPeakMemoryKB() << " KB\n";

    return 0;
}
