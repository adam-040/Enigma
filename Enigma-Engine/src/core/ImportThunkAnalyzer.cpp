#include <ghidra/ImportThunkAnalyzer.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Function.h>

namespace ghidra {

bool ImportThunkAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    if (!funcMgr) return false;

    auto* refMgr = program->getReferenceManager();
    auto* symTable = program->getSymbolTable();
    if (!refMgr || !symTable) return false;

    auto iter = funcMgr->getFunctions();
    while (iter.hasNext()) {
        auto* func = iter.next();
        if (!func || func->isThunk() || func->isExternal()) continue;

        Address entryPoint = func->getEntryPoint();

        auto refs = refMgr->getReferencesFrom(entryPoint);
        for (auto* ref : refs) {
            Address target = ref->getToAddress();

            auto symbols = symTable->getSymbols(target);
            for (auto* sym : symbols) {
                if (sym && (sym->isExternal() ||
                            sym->getName().rfind("__imp_", 0) == 0 ||
                            sym->getName().rfind("imp_", 0) == 0)) {

                    func->setThunk(true);

                    std::string cleanName = sym->getName();
                    if (cleanName.rfind("__imp_", 0) == 0) {
                        cleanName = cleanName.substr(6);
                    } else if (cleanName.rfind("imp_", 0) == 0) {
                        cleanName = cleanName.substr(4);
                    }

                    func->setName(cleanName + "_thunk");

                    auto* thunkedFunc = funcMgr->getFunctionAt(target);
                    if (thunkedFunc) {
                        func->setThunkedFunction(thunkedFunc);
                    }
                    break;
                }
            }
            if (func->isThunk()) break;
        }
    }

    return true;
}

} // namespace ghidra
