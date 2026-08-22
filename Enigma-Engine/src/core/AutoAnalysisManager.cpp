#include <ghidra/AutoAnalysisManager.h>
#include <ghidra/FunctionDiscoveryAnalyzerAdapter.h>
#include <ghidra/MainRecognitionAnalyzer.h>
#include <ghidra/DisassemblyAnalyzer.h>
#include <ghidra/ImportThunkAnalyzer.h>
#include <ghidra/FunctionAnalyzer.h>
#include <ghidra/CreateThunkAnalyzer.h>
#include <ghidra/ScalarOperandAnalyzer.h>
#include <ghidra/OperandReferenceAnalyzer.h>
#include <ghidra/DataOperandReferenceAnalyzer.h>
#include <ghidra/ConstantPropagationAnalyzer.h>
#include <ghidra/ExternalEntryFunctionAnalyzer.h>
#include <ghidra/SharedReturnAnalyzer.h>
#include <ghidra/StackVariableAnalyzer.h>
#include <ghidra/StackReferenceAnalyzer.h>
#include <ghidra/NoReturnFunctionAnalyzer.h>
#include <ghidra/FindNoReturnFunctionsAnalyzer.h>
#include <ghidra/EntryPointAnalyzer.h>
#include <ghidra/AddressTableAnalyzer.h>
#include <ghidra/DecompilerSwitchAnalyzer.h>
#include <ghidra/StringsAnalyzer.h>
#include <ghidra/CondenseFillerBytesAnalyzer.h>
#include <ghidra/DecompilerCallConventionAnalyzer.h>
#include <ghidra/ExternalSymbolResolverAnalyzer.h>
#include <ghidra/SharedReturnJumpAnalyzer.h>
#include <ghidra/EmbeddedMediaAnalyzer.h>
#include <iostream>
#include <ghidra/DWARFAnalyzer.h>
#include <ghidra/ApplyDataArchiveAnalyzer.h>
#include <ghidra/AggressiveInstructionFinderAnalyzer.h>
#include <ghidra/CallFixupAnalyzer.h>
#include <ghidra/ElfAnalyzer.h>
#include <ghidra/PortableExecutableAnalyzer.h>
#include <ghidra/MachoAnalyzer.h>
#include <ghidra/PefAnalyzer.h>
#include <ghidra/ElfScalarOperandAnalyzer.h>
#include <ghidra/MachoFunctionStartsAnalyzer.h>
#include <ghidra/MingwRelocationAnalyzer.h>
#include <ghidra/GccExceptionAnalyzer.h>
#include <ghidra/DecompilerFunctionAnalyzer.h>
#include <ghidra/PropagateExternalParametersAnalyzer.h>
#include <ghidra/CallFixupChangeAnalyzer.h>
#include <ghidra/X86FunctionPurgeAnalyzer.h>
#include <ghidra/SegmentedCallingConventionAnalyzer.h>
#include <ghidra/PEExceptionAnalyzer.h>
#include <ghidra/GuardCfgAnalyzer.h>
#include <ghidra/WindowsResourceReferenceAnalyzer.h>
#include <ghidra/TEBAnalyzer.h>
#include <ghidra/RttiAnalyzer.h>
#include <ghidra/PefDebugAnalyzer.h>
#include <ghidra/SwiftTypeMetadataAnalyzer.h>
#include <ghidra/ObjcTypeMetadataAnalyzer.h>
#include <ghidra/ObjcMessageAnalyzer.h>
#include <ghidra/GolangSymbolAnalyzer.h>
#include <ghidra/GolangStringAnalyzer.h>
#include <ghidra/RustStringAnalyzer.h>
#include <ghidra/ArmSymbolAnalyzer.h>
#include <ghidra/MipsSymbolAnalyzer.h>
#include <ghidra/MipsPreAnalyzer.h>
#include <ghidra/HexagonPrologEpilogAnalyzer.h>
#include <ghidra/HCS12ConventionAnalyzer.h>
#include <ghidra/Pic24DInitAnalyzer.h>
#include <ghidra/MachoConstructorDestructorAnalyzer.h>
#include <ghidra/CliMetadataTokenAnalyzer.h>
#include <ghidra/GnuDemanglerAnalyzer.h>
#include <ghidra/MicrosoftDemanglerAnalyzer.h>
#include <ghidra/RustDemanglerAnalyzer.h>
#include <ghidra/SwiftDemanglerAnalyzer.h>
#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/FunctionStartDataPostAnalyzer.h>
#include <ghidra/DataSectionFunctionScannerAnalyzer.h>
#include <ghidra/FunctionStartFuncAnalyzer.h>
#include <ghidra/FunctionStartPostAnalyzer.h>
#include <ghidra/FunctionStartPreFuncAnalyzer.h>
#include <ghidra/PdbAnalyzer.h>
#include <ghidra/PdbUniversalAnalyzer.h>
#include <ghidra/CoffAnalyzer.h>
#include <ghidra/CoffArchiveAnalyzer.h>
#include <ghidra/FragmentMergeAnalyzer.h>
#include <ghidra/FidAnalyzer.h>
#include <ghidra/FormatStringAnalyzer.h>
#include <ghidra/CFStringAnalyzer.h>
#include <ghidra/iOS_FixupArmSymbolsAnalyzer.h>
#include <ghidra/X86Analyzer.h>
#include <ghidra/ArmAnalyzer.h>
#include <ghidra/PowerPCAddressAnalyzer.h>
#include <ghidra/RISCVAddressAnalyzer.h>
#include <ghidra/SparcAnalyzer.h>
#include <ghidra/SparcEarlyAddressAnalyzer.h>
#include <ghidra/SH4AddressAnalyzer.h>
#include <ghidra/SH4EarlyAddressAnalyzer.h>
#include <ghidra/MipsAddressAnalyzer.h>
#include <ghidra/HexagonAnalyzer.h>
#include <ghidra/LoongsonAnalyzer.h>
#include <ghidra/Motorola68KAnalyzer.h>
#include <ghidra/NDS32Analyzer.h>
#include <ghidra/Pic16Analyzer.h>
#include <ghidra/AppleSingleDoubleAnalyzer.h>
#include <ghidra/ArmAggressiveInstructionFinderAnalyzer.h>
#include <ghidra/AARCH64PltThunkAnalyzer.h>
#include <ghidra/HexagonThunkAnalyzer.h>
#include <ghidra/HexagonUnsupportSemanticAnalyzer.h>
#include <ghidra/Pic12Analyzer.h>
#include <ghidra/Pic17c7xxAnalyzer.h>
#include <ghidra/Pic18Analyzer.h>
#include <ghidra/PicSwitchAnalyzer.h>
#include <ghidra/eBPFSyscallAnalyzer.h>
#include <ghidra/DexHeaderFormatAnalyzer.h>
#include <ghidra/DexCondenseFillerBytesAnalyzer.h>
#include <ghidra/DexExceptionHandlersAnalyzer.h>
#include <ghidra/DexMarkupDataAnalyzer.h>
#include <ghidra/DexMarkupInstructionsAnalyzer.h>
#include <ghidra/DexMarkupSwitchTableAnalyzer.h>
#include <ghidra/OatExecAnalyzer.h>
#include <ghidra/OatHeaderAnalyzer.h>
#include <ghidra/OdexHeaderFormatAnalyzer.h>
#include <ghidra/VdexHeaderAnalyzer.h>
#include <ghidra/AndroidBootLoaderAnalyzer.h>
#include <ghidra/BootImageAnalyzer.h>
#include <ghidra/iOS_Analyzer.h>
#include <ghidra/iOS_KextStubFixupAnalyzer.h>
#include <ghidra/DyldCacheAnalyzer.h>
#include <ghidra/Apple8900Analyzer.h>
#include <ghidra/DmgAnalyzer.h>
#include <ghidra/FBPK_Analyzer.h>
#include <ghidra/ArtAnalyzer.h>
#include <ghidra/BinaryPropertyListAnalyzer.h>
#include <ghidra/CramFsAnalyzer.h>
#include <ghidra/Ext4Analyzer.h>
#include <ghidra/NewExt4Analyzer.h>
#include <ghidra/DtbAnalyzer.h>
#include <ghidra/FdtAnalyzer.h>
#include <ghidra/iBootImAnalyzer.h>
#include <ghidra/Img2Analyzer.h>
#include <ghidra/Img3Analyzer.h>
#include <ghidra/LzssAnalyzer.h>
#include <ghidra/ToyAnalyzer.h>
#include <ghidra/ApplyKnownSignatureAnalyzer.h>
#include <ghidra/JavaAnalyzer.h>
#include <ghidra/JvmSwitchAnalyzer.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/Memory.h>
#include <ghidra/AnalysisScheduler.h>
#include <ghidra/AggressiveRecoveryAnalyzer.h>
#include <ghidra/FunctionBodyFinalizer.h>
#include <algorithm>
#include <future>
#include <map>

namespace ghidra {

AutoAnalysisManager::AutoAnalysisManager(Program* program)
    : program_(program),
      byteTasks_(this, analyzerTypeName(AnalyzerType::BYTE_ANALYZER)),
      instructionTasks_(this, analyzerTypeName(AnalyzerType::INSTRUCTION_ANALYZER)),
      functionTasks_(this, analyzerTypeName(AnalyzerType::FUNCTION_ANALYZER)),
      functionModifierTasks_(this, analyzerTypeName(AnalyzerType::FUNCTION_MODIFIERS_ANALYZER)),
      functionSignatureTasks_(this, analyzerTypeName(AnalyzerType::FUNCTION_SIGNATURES_ANALYZER)),
      dataTasks_(this, analyzerTypeName(AnalyzerType::DATA_ANALYZER)) {
    taskArray_[0] = &byteTasks_;
    taskArray_[1] = &instructionTasks_;
    taskArray_[2] = &functionTasks_;
    taskArray_[3] = &functionModifierTasks_;
    taskArray_[4] = &functionSignatureTasks_;
    taskArray_[5] = &dataTasks_;
    getManagerMap()[program] = this;
}

AutoAnalysisManager::~AutoAnalysisManager() {
    notifyAnalysisEnded(true);
    getManagerMap().erase(program_);
}

std::map<Program*, AutoAnalysisManager*>& AutoAnalysisManager::getManagerMap() {
    static std::map<Program*, AutoAnalysisManager*> managerMap;
    return managerMap;
}

AutoAnalysisManager* AutoAnalysisManager::getAnalysisManager(Program* program) {
    auto& map = getManagerMap();
    auto it = map.find(program);
    return it != map.end() ? it->second : nullptr;
}

bool AutoAnalysisManager::hasAutoAnalysisManager(Program* program) {
    return getAnalysisManager(program) != nullptr;
}

void AutoAnalysisManager::dispose() {
    notifyAnalysisEnded(true);
    isAnalyzing_ = false;
    pendingSchedulers_.clear();
    for (auto* taskList : taskArray_) {
        taskList->clear();
    }
    getManagerMap().erase(program_);
}

void AutoAnalysisManager::addToTaskList(std::unique_ptr<Analyzer> analyzer) {
    AnalyzerType type = analyzer->getAnalysisType();
    switch (type) {
        case AnalyzerType::BYTE_ANALYZER:
            byteTasks_.add(std::move(analyzer));
            break;
        case AnalyzerType::INSTRUCTION_ANALYZER:
            instructionTasks_.add(std::move(analyzer));
            break;
        case AnalyzerType::FUNCTION_ANALYZER:
            functionTasks_.add(std::move(analyzer));
            break;
        case AnalyzerType::FUNCTION_MODIFIERS_ANALYZER:
            functionModifierTasks_.add(std::move(analyzer));
            break;
        case AnalyzerType::FUNCTION_SIGNATURES_ANALYZER:
            functionSignatureTasks_.add(std::move(analyzer));
            break;
        case AnalyzerType::DATA_ANALYZER:
            dataTasks_.add(std::move(analyzer));
            break;
    }
}

void AutoAnalysisManager::registerAnalyzer(std::unique_ptr<Analyzer> analyzer) {
    addToTaskList(std::move(analyzer));
}

void AutoAnalysisManager::initializeDefaultAnalyzers() {
    registerAnalyzer(std::make_unique<FunctionDiscoveryAnalyzerAdapter>());
    registerAnalyzer(std::make_unique<DisassemblyAnalyzer>());
    registerAnalyzer(std::make_unique<ImportThunkAnalyzer>());
    registerAnalyzer(std::make_unique<FunctionAnalyzer>());
    registerAnalyzer(std::make_unique<CreateThunkAnalyzer>());
    registerAnalyzer(std::make_unique<ScalarOperandAnalyzer>());
    registerAnalyzer(std::make_unique<OperandReferenceAnalyzer>());
    registerAnalyzer(std::make_unique<DataOperandReferenceAnalyzer>());
    registerAnalyzer(std::make_unique<ConstantPropagationAnalyzer>());
    registerAnalyzer(std::make_unique<ExternalEntryFunctionAnalyzer>());
    registerAnalyzer(std::make_unique<SharedReturnAnalyzer>());
    registerAnalyzer(std::make_unique<StackVariableAnalyzer>());
    registerAnalyzer(std::make_unique<StackReferenceAnalyzer>());
    registerAnalyzer(std::make_unique<NoReturnFunctionAnalyzer>());
    registerAnalyzer(std::make_unique<FindNoReturnFunctionsAnalyzer>());
    registerAnalyzer(std::make_unique<EntryPointAnalyzer>());
    registerAnalyzer(std::make_unique<AddressTableAnalyzer>());
    registerAnalyzer(std::make_unique<DecompilerSwitchAnalyzer>());
    registerAnalyzer(std::make_unique<StringsAnalyzer>());
    registerAnalyzer(std::make_unique<CondenseFillerBytesAnalyzer>());
    registerAnalyzer(std::make_unique<DecompilerCallConventionAnalyzer>());
    registerAnalyzer(std::make_unique<ExternalSymbolResolverAnalyzer>());
    registerAnalyzer(std::make_unique<SharedReturnJumpAnalyzer>());
    registerAnalyzer(std::make_unique<EmbeddedMediaAnalyzer>());
    registerAnalyzer(std::make_unique<DWARFAnalyzer>());
    registerAnalyzer(std::make_unique<ApplyDataArchiveAnalyzer>());
    registerAnalyzer(std::make_unique<AggressiveInstructionFinderAnalyzer>());
    registerAnalyzer(std::make_unique<CallFixupAnalyzer>());
    registerAnalyzer(std::make_unique<ElfAnalyzer>());
    registerAnalyzer(std::make_unique<PortableExecutableAnalyzer>());
    registerAnalyzer(std::make_unique<MachoAnalyzer>());
    registerAnalyzer(std::make_unique<PefAnalyzer>());
    registerAnalyzer(std::make_unique<ElfScalarOperandAnalyzer>());
    registerAnalyzer(std::make_unique<MachoFunctionStartsAnalyzer>());
    registerAnalyzer(std::make_unique<MingwRelocationAnalyzer>());
    registerAnalyzer(std::make_unique<GccExceptionAnalyzer>());
    registerAnalyzer(std::make_unique<DecompilerFunctionAnalyzer>());
    registerAnalyzer(std::make_unique<PropagateExternalParametersAnalyzer>());
    registerAnalyzer(std::make_unique<CallFixupChangeAnalyzer>());
    registerAnalyzer(std::make_unique<X86FunctionPurgeAnalyzer>());
    registerAnalyzer(std::make_unique<SegmentedCallingConventionAnalyzer>());
    registerAnalyzer(std::make_unique<PEExceptionAnalyzer>());
    registerAnalyzer(std::make_unique<GuardCfgAnalyzer>());
    registerAnalyzer(std::make_unique<WindowsResourceReferenceAnalyzer>());
    registerAnalyzer(std::make_unique<TEBAnalyzer>());
    registerAnalyzer(std::make_unique<RttiAnalyzer>());
    registerAnalyzer(std::make_unique<PefDebugAnalyzer>());
    registerAnalyzer(std::make_unique<SwiftTypeMetadataAnalyzer>());
    registerAnalyzer(std::make_unique<ObjcTypeMetadataAnalyzer>());
    registerAnalyzer(std::make_unique<ObjcMessageAnalyzer>());
    registerAnalyzer(std::make_unique<GolangSymbolAnalyzer>());
    registerAnalyzer(std::make_unique<GolangStringAnalyzer>());
    registerAnalyzer(std::make_unique<RustStringAnalyzer>());
    registerAnalyzer(std::make_unique<ArmSymbolAnalyzer>());
    registerAnalyzer(std::make_unique<MipsSymbolAnalyzer>());
    registerAnalyzer(std::make_unique<MipsPreAnalyzer>());
    registerAnalyzer(std::make_unique<HexagonPrologEpilogAnalyzer>());
    registerAnalyzer(std::make_unique<HCS12ConventionAnalyzer>());
    registerAnalyzer(std::make_unique<Pic24DInitAnalyzer>());
    registerAnalyzer(std::make_unique<CliMetadataTokenAnalyzer>());
    registerAnalyzer(std::make_unique<GnuDemanglerAnalyzer>());
    registerAnalyzer(std::make_unique<MicrosoftDemanglerAnalyzer>());
    registerAnalyzer(std::make_unique<RustDemanglerAnalyzer>());
    registerAnalyzer(std::make_unique<SwiftDemanglerAnalyzer>());
    registerAnalyzer(std::make_unique<FunctionStartAnalyzer>());
    registerAnalyzer(std::make_unique<DataSectionFunctionScannerAnalyzer>());
    registerAnalyzer(std::make_unique<FunctionStartDataPostAnalyzer>());
    registerAnalyzer(std::make_unique<FunctionStartFuncAnalyzer>());
    // NOTE: FunctionStartPostAnalyzer disabled - byte-by-byte scan is too slow for large binaries
    registerAnalyzer(std::make_unique<FunctionStartPreFuncAnalyzer>());
    registerAnalyzer(std::make_unique<PdbAnalyzer>());
    registerAnalyzer(std::make_unique<PdbUniversalAnalyzer>());
    registerAnalyzer(std::make_unique<CoffAnalyzer>());
    registerAnalyzer(std::make_unique<CoffArchiveAnalyzer>());
    registerAnalyzer(std::make_unique<FidAnalyzer>());
    registerAnalyzer(std::make_unique<ApplyKnownSignatureAnalyzer>());
    registerAnalyzer(std::make_unique<FormatStringAnalyzer>());
    registerAnalyzer(std::make_unique<CFStringAnalyzer>());
    registerAnalyzer(std::make_unique<MachoConstructorDestructorAnalyzer>());
    registerAnalyzer(std::make_unique<iOS_FixupArmSymbolsAnalyzer>());
    registerAnalyzer(std::make_unique<X86Analyzer>());
    registerAnalyzer(std::make_unique<ArmAnalyzer>());
    registerAnalyzer(std::make_unique<PowerPCAddressAnalyzer>());
    registerAnalyzer(std::make_unique<RISCVAddressAnalyzer>());
    registerAnalyzer(std::make_unique<SparcAnalyzer>());
    registerAnalyzer(std::make_unique<SparcEarlyAddressAnalyzer>());
    registerAnalyzer(std::make_unique<SH4AddressAnalyzer>());
    registerAnalyzer(std::make_unique<SH4EarlyAddressAnalyzer>());
    registerAnalyzer(std::make_unique<MipsAddressAnalyzer>());
    registerAnalyzer(std::make_unique<HexagonAnalyzer>());
    registerAnalyzer(std::make_unique<LoongsonAnalyzer>());
    registerAnalyzer(std::make_unique<Motorola68KAnalyzer>());
    registerAnalyzer(std::make_unique<NDS32Analyzer>());
    registerAnalyzer(std::make_unique<Pic16Analyzer>());
    registerAnalyzer(std::make_unique<ToyAnalyzer>());
    registerAnalyzer(std::make_unique<AppleSingleDoubleAnalyzer>());
    registerAnalyzer(std::make_unique<ArmAggressiveInstructionFinderAnalyzer>());
    registerAnalyzer(std::make_unique<AARCH64PltThunkAnalyzer>());
    registerAnalyzer(std::make_unique<HexagonThunkAnalyzer>());
    registerAnalyzer(std::make_unique<HexagonUnsupportSemanticAnalyzer>());
    registerAnalyzer(std::make_unique<Pic12Analyzer>());
    registerAnalyzer(std::make_unique<Pic17c7xxAnalyzer>());
    registerAnalyzer(std::make_unique<Pic18Analyzer>());
    registerAnalyzer(std::make_unique<PicSwitchAnalyzer>());
    registerAnalyzer(std::make_unique<eBPFSyscallAnalyzer>());
    registerAnalyzer(std::make_unique<DexHeaderFormatAnalyzer>());
    registerAnalyzer(std::make_unique<DexCondenseFillerBytesAnalyzer>());
    registerAnalyzer(std::make_unique<DexExceptionHandlersAnalyzer>());
    registerAnalyzer(std::make_unique<DexMarkupDataAnalyzer>());
    registerAnalyzer(std::make_unique<DexMarkupInstructionsAnalyzer>());
    registerAnalyzer(std::make_unique<DexMarkupSwitchTableAnalyzer>());
    registerAnalyzer(std::make_unique<OatExecAnalyzer>());
    registerAnalyzer(std::make_unique<OatHeaderAnalyzer>());
    registerAnalyzer(std::make_unique<OdexHeaderFormatAnalyzer>());
    registerAnalyzer(std::make_unique<VdexHeaderAnalyzer>());
    registerAnalyzer(std::make_unique<AndroidBootLoaderAnalyzer>());
    registerAnalyzer(std::make_unique<BootImageAnalyzer>());
    registerAnalyzer(std::make_unique<iOS_Analyzer>());
    registerAnalyzer(std::make_unique<iOS_KextStubFixupAnalyzer>());
    registerAnalyzer(std::make_unique<DyldCacheAnalyzer>());
    registerAnalyzer(std::make_unique<Apple8900Analyzer>());
    registerAnalyzer(std::make_unique<DmgAnalyzer>());
    registerAnalyzer(std::make_unique<FBPK_Analyzer>());
    registerAnalyzer(std::make_unique<ArtAnalyzer>());
    registerAnalyzer(std::make_unique<BinaryPropertyListAnalyzer>());
    registerAnalyzer(std::make_unique<CramFsAnalyzer>());
    registerAnalyzer(std::make_unique<Ext4Analyzer>());
    registerAnalyzer(std::make_unique<NewExt4Analyzer>());
    registerAnalyzer(std::make_unique<DtbAnalyzer>());
    registerAnalyzer(std::make_unique<FdtAnalyzer>());
    registerAnalyzer(std::make_unique<iBootImAnalyzer>());
    registerAnalyzer(std::make_unique<Img2Analyzer>());
    registerAnalyzer(std::make_unique<Img3Analyzer>());
    registerAnalyzer(std::make_unique<LzssAnalyzer>());
    registerAnalyzer(std::make_unique<JavaAnalyzer>());
    registerAnalyzer(std::make_unique<JvmSwitchAnalyzer>());
    registerAnalyzer(std::make_unique<FragmentMergeAnalyzer>());
    // Late ImportThunkAnalyzer pass: processes functions created by later analyzers
    // (FunctionStart*, FunctionDiscovery*, etc.) and catches thunks whose data
    // references were only created after reference-creating analyzers ran.
    registerAnalyzer(std::make_unique<ImportThunkAnalyzer>());
    registerAnalyzer(std::make_unique<MainRecognitionAnalyzer>());
    // PHASE B: Aggressive recovery — disabled by default. Enable manually for
    // heuristic function recovery from orphan islands, gap CALL targets, and tiny helpers.
    // Confidence scoring and bookmark creation included. NEVER enable in production.
    registerAnalyzer(std::make_unique<FunctionBodyFinalizer>());
    registerAnalyzer(std::make_unique<AggressiveRecoveryAnalyzer>());
}

Analyzer* AutoAnalysisManager::getAnalyzer(const std::string& name) const {
    for (auto* taskList : taskArray_) {
        for (const auto& s : taskList->getSchedulers()) {
            if (s->getName() == name) {
                return s->getAnalyzer();
            }
        }
    }
    return nullptr;
}

std::vector<Analyzer*> AutoAnalysisManager::getAnalyzers() const {
    std::vector<Analyzer*> result;
    for (auto* taskList : taskArray_) {
        for (const auto& s : taskList->getSchedulers()) {
            result.push_back(s->getAnalyzer());
        }
    }
    return result;
}

AnalysisTaskList* AutoAnalysisManager::getTaskList(AnalyzerType type) {
    return taskArray_[static_cast<int>(type)];
}

AddressSet AutoAnalysisManager::buildFullAddressSet() {
    AddressSet entireSet;
    if (!program_) return entireSet;
    auto* memory = program_->getMemory();
    if (memory) {
        Address minAddress = program_->getMinAddress();
        Address maxAddress = program_->getMaxAddress();
        if (minAddress != Address::NO_ADDRESS && maxAddress != Address::NO_ADDRESS && minAddress < maxAddress) {
            entireSet.addRange(minAddress, maxAddress);
        } else {
            Address imageBase = program_->getImageBase();
            entireSet.addRange(imageBase, imageBase.add(0x100000));
        }
    } else {
        Address imageBase = program_->getImageBase();
        entireSet.addRange(imageBase, imageBase.add(0x100000));
    }
    return entireSet;
}

void AutoAnalysisManager::analyze(TaskMonitor* monitor) {
    if (!program_) return;
    isAnalyzing_ = true;
    AddressSet entireSet = buildFullAddressSet();
    analyzeRange(entireSet, monitor);
    processSchedulerQueue();
    notifyAnalysisEnded(monitor ? monitor->isCancelled() : false);
    isAnalyzing_ = false;
}

void AutoAnalysisManager::analyzeRange(const AddressSetView& set, TaskMonitor* monitor) {
    if (!program_) return;

    for (auto* taskList : taskArray_) {
        for (const auto& scheduler : taskList->getSchedulers()) {
            if (monitor && monitor->isCancelled()) break;
            Analyzer* analyzer = scheduler->getAnalyzer();
            bool shouldRun = false;
            try {
                shouldRun = analyzer->canAnalyze(program_) && analyzer->getDefaultEnablement(program_);
            } catch (...) {
                shouldRun = false;
            }
            if (shouldRun) {
                if (monitor) {
                    monitor->setMessage("Running analyzer: " + analyzer->getName());
                }
                std::cerr << "[INFO] AutoAnalysisManager: starting analyzer '"
                          << analyzer->getName() << "'" << std::endl;
                scheduler->added(set);
                scheduler->runAnalyzer(program_, monitor, log_);
            }
        }
    }
}

void AutoAnalysisManager::analyzeOne(Analyzer* analyzer, const AddressSetView& set,
                                     TaskMonitor* monitor, MessageLog& log) {
    if (!program_ || !analyzer) return;
    bool shouldRun = false;
    try {
        shouldRun = analyzer->canAnalyze(program_) && analyzer->getDefaultEnablement(program_);
    } catch (...) {
        shouldRun = false;
    }
    if (!shouldRun) return;
    if (monitor) {
        monitor->setMessage("Running analyzer: " + analyzer->getName());
    }
    analyzer->added(program_, set, monitor, log);
}

void AutoAnalysisManager::startAnalysis(TaskMonitor* monitor) {
    analyze(monitor);
}

void AutoAnalysisManager::startAnalysis(TaskMonitor* monitor, bool printTimes) {
    analyze(monitor);
}

void AutoAnalysisManager::scheduleOneTimeAnalysis(Analyzer* analyzer, const AddressSetView& set) {
    if (!analyzer) return;
    MessageLog log;
    analyzeOne(analyzer, set, nullptr, log);
}

void AutoAnalysisManager::waitForAnalysis(int timeoutMs, TaskMonitor* monitor) {
    processSchedulerQueue();
}

void AutoAnalysisManager::reAnalyzeAll(const AddressSetView& set) {
    if (!program_) return;
    isAnalyzing_ = true;
    for (auto* taskList : taskArray_) {
        for (const auto& scheduler : taskList->getSchedulers()) {
            Analyzer* analyzer = scheduler->getAnalyzer();
            if (analyzer && analyzer->canAnalyze(program_)) {
                scheduler->removed(set);
            }
        }
    }
    for (auto* taskList : taskArray_) {
        for (const auto& scheduler : taskList->getSchedulers()) {
            Analyzer* analyzer = scheduler->getAnalyzer();
            if (analyzer) {
                bool shouldRun = false;
                try {
                    shouldRun = analyzer->canAnalyze(program_) && analyzer->getDefaultEnablement(program_);
                } catch (...) {
                    shouldRun = false;
                }
                if (shouldRun) {
                    scheduler->added(set);
                    scheduler->runAnalyzer(program_, nullptr, log_);
                }
            }
        }
    }
    isAnalyzing_ = false;
}

void AutoAnalysisManager::cancelQueuedTasks() {
    pendingSchedulers_.clear();
}

void AutoAnalysisManager::setIgnoreChanges(bool ignore) {
    ignoreChanges_ = ignore;
}

void AutoAnalysisManager::scheduleTask(AnalysisScheduler* scheduler) {
    pendingSchedulers_.push_back(scheduler);
}

void AutoAnalysisManager::processSchedulerQueue() {
    if (!program_) return;
    int maxIterations = 10;
    int iteration = 0;
    while (!pendingSchedulers_.empty() && iteration < maxIterations) {
        std::vector<AnalysisScheduler*> currentQueue = std::move(pendingSchedulers_);
        pendingSchedulers_.clear();
        for (auto* scheduler : currentQueue) {
            scheduler->runAnalyzer(program_, nullptr, log_);
        }
        iteration++;
    }
    pendingSchedulers_.clear();
}

// Event-driven change notifications
void AutoAnalysisManager::blockAdded(const AddressSetView& set) {
    if (ignoreChanges_) return;
    byteTasks_.notifyAdded(set);
}

void AutoAnalysisManager::codeDefined(const AddressSetView& set) {
    if (ignoreChanges_) return;
    instructionTasks_.notifyAdded(set);
}

void AutoAnalysisManager::codeDefined(const Address& addr) {
    if (ignoreChanges_) return;
    instructionTasks_.notifyAdded(addr);
}

void AutoAnalysisManager::dataDefined(const AddressSetView& set) {
    if (ignoreChanges_) return;
    dataTasks_.notifyAdded(set);
}

void AutoAnalysisManager::functionDefined(const AddressSetView& set) {
    if (ignoreChanges_) return;
    functionTasks_.notifyAdded(set);
}

void AutoAnalysisManager::functionDefined(const Address& addr) {
    if (ignoreChanges_) return;
    functionTasks_.notifyAdded(addr);
}

void AutoAnalysisManager::functionModifierChanged(const AddressSetView& set) {
    if (ignoreChanges_) return;
    functionModifierTasks_.notifyAdded(set);
}

void AutoAnalysisManager::functionModifierChanged(const Address& addr) {
    if (ignoreChanges_) return;
    functionModifierTasks_.notifyAdded(addr);
}

void AutoAnalysisManager::functionSignatureChanged(const AddressSetView& set) {
    if (ignoreChanges_) return;
    functionSignatureTasks_.notifyAdded(set);
}

void AutoAnalysisManager::functionSignatureChanged(const Address& addr) {
    if (ignoreChanges_) return;
    functionSignatureTasks_.notifyAdded(addr);
}

void AutoAnalysisManager::externalAdded(const Address& addr) {
    if (ignoreChanges_) return;
    byteTasks_.notifyAdded(addr);
}

void AutoAnalysisManager::addListener(AutoAnalysisManagerListener* listener) {
    if (std::find(listeners_.begin(), listeners_.end(), listener) == listeners_.end()) {
        listeners_.push_back(listener);
    }
}

void AutoAnalysisManager::removeListener(AutoAnalysisManagerListener* listener) {
    auto it = std::find(listeners_.begin(), listeners_.end(), listener);
    if (it != listeners_.end()) {
        listeners_.erase(it);
    }
}

void AutoAnalysisManager::notifyAnalysisEnded(bool isCancelled) {
    for (auto* listener : listeners_) {
        listener->analysisEnded(this, isCancelled);
    }
    for (auto* taskList : taskArray_) {
        taskList->notifyAnalysisEnded(program_);
    }
}

void AutoAnalysisManager::registerOptions() {
    for (auto* taskList : taskArray_) {
        for (const auto& scheduler : taskList->getSchedulers()) {
            Analyzer* analyzer = scheduler->getAnalyzer();
            if (analyzer) {
                Options opts(analyzer->getName());
                analyzer->registerOptions(opts, program_);
            }
        }
    }
}

void AutoAnalysisManager::initializeOptions() {
    for (auto* taskList : taskArray_) {
        for (const auto& scheduler : taskList->getSchedulers()) {
            Analyzer* analyzer = scheduler->getAnalyzer();
            if (analyzer) {
                Options opts(analyzer->getName());
                analyzer->optionsChanged(opts, program_);
            }
        }
    }
}

} // namespace ghidra
