#include <ghidra/DecompilerFunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Language.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/DecompilerAdapter.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>
#include <cstdlib>

namespace ghidra {

static const char* ENABLED_PROPERTY = "DecompilerParameterAnalyzer.enabled";
static const char* OPTION_NAME_CLEAR_LEVEL = "Analysis Clear Level";
static const char* OPTION_NAME_COMMIT_DATA_TYPES = "Commit Data Types";
static const char* OPTION_NAME_COMMIT_VOID_RETURN = "Commit Void Return Values";
static const char* OPTION_NAME_DECOMPILER_TIMEOUT_SECS = "Analysis Decompiler Timeout (sec)";
static const char* OPTION_DESCRIPTION_CLEAR_LEVEL = "Set level for amount of existing parameter data to clear";
static const char* OPTION_DESCRIPTION_COMMIT_DATA_TYPES = "Turn on to commit data types";
static const char* OPTION_DESCRIPTION_COMMIT_VOID_RETURN = "Turn on to lock in 'void' return values";
static const char* OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS = "Set timeout in seconds for analyzer decompiler calls.";

static constexpr long long MEDIUM_SIZE_PROGRAM = 2LL * 1024 * 1024;

DecompilerFunctionAnalyzer::DecompilerFunctionAnalyzer()
    : AbstractAnalyzer("Decompiler Parameter ID",
                       "Creates parameter and local variables for a Function using Decompiler.\n"
                       "WARNING: This can take a SIGNIFICANT Amount of Time!\n"
                       "         Turned off by default for large programs\n"
                       "You can run this later using \"Analysis->Decompiler Parameter ID\"",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after().after());
    setSupportsOneTimeAnalysis();
}

bool DecompilerFunctionAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    Language* lang = program->getLanguage();
    return lang && lang->supportsPcode();
}

bool DecompilerFunctionAnalyzer::getDefaultEnablement(Program* program) const {
    if (!program) return false;

    const char* env = std::getenv(ENABLED_PROPERTY);
    if (env) {
        std::string val(env);
        if (val == "false" || val == "0") {
            return false;
        }
    }

    long long numAddr = program->getMemory()->getSize();
    if (numAddr >= MEDIUM_SIZE_PROGRAM) {
        return false;
    }

    return program->getExecutableFormat() == "Portable Executable";
}

void DecompilerFunctionAnalyzer::registerOptions(Options& options, Program* program) {
    std::vector<std::string> sourceTypeValues = {
        "DEFAULT", "ANALYSIS", "USER_DEFINED", "IMPORTED", "AI"
    };
    options.registerEnum(OPTION_NAME_CLEAR_LEVEL, sourceTypeValues, 1,
                         OPTION_DESCRIPTION_CLEAR_LEVEL);
    options.registerBool(OPTION_NAME_COMMIT_DATA_TYPES, commitDataTypesOption_,
                         OPTION_DESCRIPTION_COMMIT_DATA_TYPES);
    options.registerBool(OPTION_NAME_COMMIT_VOID_RETURN, commitVoidReturnOption_,
                         OPTION_DESCRIPTION_COMMIT_VOID_RETURN);
    options.registerInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS, decompilerTimeoutSecondsOption_,
                        OPTION_DESCRIPTION_DECOMPILER_TIMEOUT_SECS);
}

void DecompilerFunctionAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(OPTION_NAME_CLEAR_LEVEL)) {
        clearLevelOption_ = options.getEnumIndex(OPTION_NAME_CLEAR_LEVEL);
    }
    if (options.hasOption(OPTION_NAME_COMMIT_DATA_TYPES)) {
        commitDataTypesOption_ = options.getBool(OPTION_NAME_COMMIT_DATA_TYPES);
    }
    if (options.hasOption(OPTION_NAME_COMMIT_VOID_RETURN)) {
        commitVoidReturnOption_ = options.getBool(OPTION_NAME_COMMIT_VOID_RETURN);
    }
    if (options.hasOption(OPTION_NAME_DECOMPILER_TIMEOUT_SECS)) {
        decompilerTimeoutSecondsOption_ = options.getInt(OPTION_NAME_DECOMPILER_TIMEOUT_SECS);
    }
}

bool DecompilerFunctionAnalyzer::added(Program* program, const AddressSetView& set,
                                        TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!funcMgr || !listing) return true;

    // Create decompiler adapter
    auto adapter = createDecompilerAdapter();
    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!adapter || !programDB || !adapter->initialize(programDB)) {
        Msg::info(getName(), "Decompiler not available. SLEIGH specs may be missing.");
        return true;
    }

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    if (monitor) {
        monitor->initialize(static_cast<int>(funcIter.remaining()));
    }

    int count = 0;
    int decompiledCount = 0;
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(++count);

        Function* func = funcIter.next();
        if (!func) continue;

        monitor->setMessage("Decompiling: " + func->getName());

        auto decompRes = adapter->decompileFunction(func, decompilerTimeoutSecondsOption_);

        if (decompRes.success && !decompRes.cCode.empty()) {
            // Extract just the function signature (line before '{')
            std::string signature = decompRes.cCode;
            auto bracePos = signature.find('{');
            if (bracePos != std::string::npos) {
                // Trim trailing whitespace and add ';'
                signature = signature.substr(0, bracePos);
                while (!signature.empty() &&
                       (signature.back() == ' ' || signature.back() == '\n' || signature.back() == '\r' || signature.back() == '\t')) {
                    signature.pop_back();
                }
                signature += ";";
            }

            // Add signature as a pre-comment on the function entry instruction
            Instruction* entryInstr = listing->getInstructionAt(func->getEntryPoint());
            if (entryInstr) {
                entryInstr->setPreComment(signature);
            }
            decompiledCount++;
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Decompiled " + std::to_string(decompiledCount) +
                            " functions");
    }

    return true;
}

} // namespace ghidra
