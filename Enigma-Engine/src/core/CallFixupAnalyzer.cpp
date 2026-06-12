#include <ghidra/CallFixupAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/RefType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <unordered_map>
#include <string>

namespace ghidra {

namespace {

// Known call-fixup function name patterns (function_name -> fixup_name)
const std::unordered_map<std::string, std::string> kKnownFixups = {
    {"__chkstk", "__chkstk"},
    {"_chkstk", "_chkstk"},
    {"__alloca", "__alloca"},
    {"_alloca", "_alloca"},
    {"memset", "memset"},
    {"memcpy", "memcpy"},
    {"memmove", "memmove"},
    {"__memcpy", "__memcpy"},
    {"strcpy", "strcpy"},
    {"strncpy", "strncpy"},
    {"strcat", "strcat"},
    {"strncat", "strncat"},
    {"__strcpy_chk", "__strcpy_chk"},
    {"__stpcpy_chk", "__stpcpy_chk"},
    {"__stpcpy", "__stpcpy"},
    {"__inline_memset", "__inline_memset"},
    {"__inline_memcpy", "__inline_memcpy"},
    {"_ftol", "_ftol"},
    {"_ftol2", "_ftol2"},
    {"__libm_sse2_sincos_", "__libm_sse2_sincos_"}
};

// Known non-returning functions that should get CALL_RETURN override
const std::unordered_map<std::string, bool> kNonReturning = {
    {"exit", true},
    {"_exit", true},
    {"abort", true},
    {"__assert", true},
    {"__assert_fail", true},
    {"longjmp", true},
    {"_longjmp", true},
    {"siglongjmp", true},
    {"quick_exit", true},
    {"_Exit", true}
};

static std::string stripLibIdConflict(const std::string& name) {
    static const std::string prefix = "libID_conflict_";
    if (name.compare(0, prefix.size(), prefix) == 0) {
        return name.substr(prefix.size());
    }
    return name;
}

static std::string lookupFixup(const std::string& rawName) {
    // Strip libID prefix
    std::string name = stripLibIdConflict(rawName);

    // Try exact match
    auto it = kKnownFixups.find(name);
    if (it != kKnownFixups.end()) return it->second;

    // Try _ prefix
    it = kKnownFixups.find("_" + name);
    if (it != kKnownFixups.end()) return it->second;

    // Try __ prefix
    it = kKnownFixups.find("__" + name);
    if (it != kKnownFixups.end()) return it->second;

    return "";
}

} // anonymous namespace

CallFixupAnalyzer::CallFixupAnalyzer()
    : AbstractAnalyzer("Call-Fixup Installer",
                       "Installs Call-Fixup overrides on known library functions.",
                       AnalyzerType::FUNCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

CallFixupAnalyzer::CallFixupAnalyzer(const std::string& name, AnalyzerType type, bool supportsOneTime)
    : AbstractAnalyzer(name, "Installs Call-Fixup overrides on known library functions.", type) {
    setPriority(AnalysisPriority::DISASSEMBLY.after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(supportsOneTime);
}

bool CallFixupAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    Listing* listing = program->getListing();
    if (!funcMgr || !refMgr || !listing) return false;

    if (monitor) monitor->setMessage("Installing call fixups...");

    FunctionIterator funcIter = funcMgr->getFunctions(set, true);
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        Function* function = funcIter.next();
        if (!function) continue;

        const std::string& funcName = function->getName();

        // Check for known call fixup
        std::string fixupName = lookupFixup(funcName);
        if (!fixupName.empty() && function->getCallFixup().empty()) {
            function->setCallFixup(fixupName);
        }

        bool hasCallFixup = !function->getCallFixup().empty();
        bool noReturn = function->hasNoReturn();

        // Check if this is a known non-returning function (even if not flagged yet)
        if (!noReturn) {
            auto nrIt = kNonReturning.find(funcName);
            if (nrIt != kNonReturning.end()) {
                function->setHasNoReturn(true);
                noReturn = true;
            }
        }

        if (!noReturn && !hasCallFixup) continue;

        // For non-returning functions, set CALL_RETURN override on all call references
        std::vector<Reference*> refs = refMgr->getReferencesTo(function->getEntryPoint());
        for (Reference* ref : refs) {
            if (!ref || !ref->getReferenceType()->isCall()) continue;

            Address fromAddr = ref->getFromAddress();
            Instruction* instr = listing->getInstructionAt(fromAddr);
            if (!instr) continue;

            if (instr->getFlowOverride() != FlowOverride::CALL_RETURN) {
                instr->setFlowOverride(FlowOverride::CALL_RETURN);
            }
        }
    }

    return true;
}

} // namespace ghidra
