#include <ghidra/FindNoReturnFunctionsAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/RefType.h>
#include <ghidra/FlowOverride.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Varnode.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <map>

namespace ghidra {

FindNoReturnFunctionsAnalyzer::FindNoReturnFunctionsAnalyzer()
    : AbstractAnalyzer("Non-Returning Functions - Discovered",
                       "Discovers indications that functions do not return.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY.after());
    setSupportsOneTimeAnalysis();
}

bool FindNoReturnFunctionsAnalyzer::added(Program* program, const AddressSetView& set,
                                           TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* refMgr = program->getReferenceManager();
    auto* funcMgr = program->getFunctionManager();
    if (!listing || !refMgr || !funcMgr) return false;

    if (monitor) {
        monitor->setMessage("Finding non-returning functions");
    }

    std::map<Address, int> evidenceCount;

    auto instructions = listing->getInstructions(set);
    for (Instruction* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;
        if (!instr) continue;

        FlowType* ftype = instr->getFlowType();
        if (!ftype || !ftype->isCall()) continue;
        if (!ftype->hasFallthrough()) continue;

        Address fallThru = instr->getFallThrough();
        if (!fallThru.isValid()) continue;

        Address target;
        const auto& flows = instr->getFlows();
        if (!flows.empty()) {
            target = flows[0]->getAddress();
        } else {
            continue;
        }

        if (funcMgr->getFunctionAt(fallThru)) {
            evidenceCount[target]++;
            continue;
        }

        if (listing->getDefinedDataContaining(fallThru)) {
            evidenceCount[target]++;
            continue;
        }

        FunctionIterator funcIter = funcMgr->getFunctions(fallThru);
        if (funcIter.hasNext()) {
            Function* func = funcIter.next();
            if (func && fallThru.compareTo(func->getEntryPoint()) <= 0) {
                evidenceCount[target]++;
            }
        }
    }

    for (auto& kv : evidenceCount) {
        if (kv.second >= evidenceThresholdFunctions_) {
            setFunctionNonReturning(program, kv.first, log);
            setNoFallThru(program, kv.first);
            fixCallingFunctionBody(program, kv.first);
        }
    }

    return true;
}

void FindNoReturnFunctionsAnalyzer::setFunctionNonReturning(Program* program, const Address& entry,
                                                              MessageLog& log) {
    auto* funcMgr = program->getFunctionManager();
    Function* func = funcMgr->getFunctionAt(entry);
    if (!func) {
        func = funcMgr->createFunction("", entry, AddressSet(entry, entry),
                                        SourceType::ANALYSIS);
    }
    if (!func) {
        log.append("Failed to create non-returning function at " + entry.toString());
        return;
    }

    func->setHasNoReturn(true);

    if (createBookmarksEnabled_) {
        program->getBookmarkManager()->setBookmark(
            entry, "Analysis", "Non-Returning Function Found");
    }
}

void FindNoReturnFunctionsAnalyzer::setNoFallThru(Program* program, const Address& entry) {
    auto* refMgr = program->getReferenceManager();
    auto* listing = program->getListing();
    if (!refMgr || !listing) return;

    auto refsTo = refMgr->getReferencesTo(entry);
    for (auto* ref : refsTo) {
        if (!ref) continue;
        const RefType* refType = ref->getReferenceType();
        if (!refType || !refType->isCall()) continue;

        Address fromAddr = ref->getFromAddress();
        Instruction* instr = listing->getInstructionAt(fromAddr);
        if (!instr) continue;

        if (instr->getFallThrough().isValid()) {
            instr->setFlowOverride(FlowOverride::CALL_RETURN);
        }
    }
}

void FindNoReturnFunctionsAnalyzer::fixCallingFunctionBody(Program* program, const Address& entry) {
    auto* refMgr = program->getReferenceManager();
    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!refMgr || !funcMgr || !listing) return;

    auto refsTo = refMgr->getReferencesTo(entry);
    AddressSet fixedSet;

    for (auto* ref : refsTo) {
        if (!ref) continue;
        const RefType* refType = ref->getReferenceType();
        if (!refType || !refType->isCall()) continue;

        Address fromAddr = ref->getFromAddress();
        if (fixedSet.contains(fromAddr)) continue;

        Function* callingFunc = funcMgr->getFunctionContaining(fromAddr);
        if (!callingFunc) continue;

        const AddressSet& oldBody = callingFunc->getBody();
        AddressSet newBody;
        if (!oldBody.isEmpty()) {
            newBody.add(oldBody.getMinAddress(), oldBody.getMaxAddress());
        }

        Instruction* callInstr = listing->getInstructionAt(fromAddr);
        if (callInstr) {
            Address fallAfter = callInstr->getFallThrough();
            if (fallAfter.isValid() && oldBody.contains(fallAfter)) {
                newBody.remove(fallAfter, oldBody.getMaxAddress());
            }
        }

        if (!newBody.isEmpty()) {
            funcMgr->createFunction(callingFunc->getName(),
                                     callingFunc->getEntryPoint(),
                                     newBody, SourceType::ANALYSIS);
        }

        if (!oldBody.isEmpty()) {
            fixedSet.add(oldBody.getMinAddress(), oldBody.getMaxAddress());
        }
    }
}

bool FindNoReturnFunctionsAnalyzer::getDefaultEnablement(Program* program) const {
    return true;
}

void FindNoReturnFunctionsAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerInt("Function Non-return Threshold", evidenceThresholdFunctions_,
                        "Number of indications before marking function non-returning.");
    options.registerBool("Repair Flow Damage", repairDamageEnabled_,
                         "Repair any flow after a call to found non-returning functions.");
    options.registerBool("Create Analysis Bookmarks", createBookmarksEnabled_,
                         "Create bookmark on each function marked as non-returning.");
}

void FindNoReturnFunctionsAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Function Non-return Threshold"))
        evidenceThresholdFunctions_ = options.getInt("Function Non-return Threshold");
    if (options.hasOption("Repair Flow Damage"))
        repairDamageEnabled_ = options.getBool("Repair Flow Damage");
    if (options.hasOption("Create Analysis Bookmarks"))
        createBookmarksEnabled_ = options.getBool("Create Analysis Bookmarks");
}

} // namespace ghidra
