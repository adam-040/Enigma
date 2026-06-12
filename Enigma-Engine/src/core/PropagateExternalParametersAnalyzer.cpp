#include <ghidra/PropagateExternalParametersAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/CodeUnit.h>
#include <ghidra/Variable.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressIterator.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

PropagateExternalParametersAnalyzer::PropagateExternalParametersAnalyzer()
    : AbstractAnalyzer("WindowsPE x86 Propagate External Parameters",
                       "Propagates parameter info as EOL comments on PUSH instructions before external calls.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION.after().after().after().after().after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool PropagateExternalParametersAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getExecutableFormat() == "Portable Executable (PE)";
}

bool PropagateExternalParametersAnalyzer::added(Program* program, const AddressSetView& set,
                                                 TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    if (monitor) monitor->setMessage("Propagating external function parameters...");

    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    SymbolTable* symTable = program->getSymbolTable();
    if (!listing || !funcMgr || !refMgr || !symTable) return true;

    // Iterate external entry points
    auto entryPoints = symTable->getExternalEntryPoints();
    for (const Address& entryAddr : entryPoints) {
        if (monitor && monitor->isCancelled()) break;

        Function* extFunc = funcMgr->getFunctionAt(entryAddr);
        if (!extFunc) continue;

        auto params = extFunc->getParameters();
        if (params.empty()) continue;

        std::string funcName = extFunc->getName();

        // Find call sites for this external function
        const auto& callRefs = extFunc->getReferences();
        for (Reference* ref : callRefs) {
            if (monitor && monitor->isCancelled()) break;
            if (!ref) continue;

            Address fromAddr = ref->getFromAddress();
            Instruction* instr = listing->getInstructionAt(fromAddr);
            if (!instr) continue;

            std::string mnemonic = instr->getMnemonicString();
            if (mnemonic != "CALL") continue;

            // Walk backwards from the call to find PUSH instructions
            Function* callingFunc = funcMgr->getFunctionContaining(fromAddr);
            if (!callingFunc) continue;

            const AddressSet& body = callingFunc->getBody();
            Address addr = fromAddr.previous();
            if (!addr.isValid()) continue;

            int foundPushes = 0;
            int nestedCalls = 0;
            std::vector<Address> pushAddrs;

            while (addr.isValid() && body.contains(addr) && foundPushes < static_cast<int>(params.size())) {
                if (monitor && monitor->isCancelled()) break;

                if (nestedCalls > 0) {
                    nestedCalls--;
                } else {
                    Instruction* prevInstr = listing->getInstructionAt(addr);
                    if (prevInstr) {
                        std::string prevMnemonic = prevInstr->getMnemonicString();
                        if (prevMnemonic == "CALL") {
                            // Skip pushes for nested calls
                            Function* nestedFunc = funcMgr->getFunctionContaining(addr);
                            if (nestedFunc) {
                                auto nestedParams = nestedFunc->getParameters();
                                nestedCalls = static_cast<int>(nestedParams.size());
                            }
                        } else if (prevMnemonic == "PUSH") {
                            pushAddrs.push_back(addr);
                            foundPushes++;
                        }
                    }
                }

                addr = addr.previous();
            }

            // Add EOL comments on the PUSH instructions
            int paramIdx = 0;
            for (auto it = pushAddrs.rbegin(); it != pushAddrs.rend() && paramIdx < static_cast<int>(params.size()); ++it, ++paramIdx) {
                CodeUnit* cu = listing->getCodeUnitAt(*it);
                if (cu) {
                    Variable* param = params[paramIdx];
                    std::string dataTypeName = param->getDataType() ? param->getDataType()->getName() : "unknown";
                    std::string comment = dataTypeName + " " + param->getName() + " for " + funcName;
                    cu->setComment(comment);
                }
            }
        }
    }

    if (monitor) monitor->setMessage("Propagated external parameters successfully.");
    return true;
}

} // namespace ghidra
