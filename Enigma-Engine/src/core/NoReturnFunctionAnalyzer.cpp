#include <ghidra/NoReturnFunctionAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/Symbol.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/AddressSet.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

namespace ghidra {

NoReturnFunctionAnalyzer::NoReturnFunctionAnalyzer()
    : AbstractAnalyzer("Non-Returning Functions - Known",
                       "Locates known functions by name, that generally do not return (exit, abort, etc).",
                       AnalyzerType::BYTE_ANALYZER) {
    setDefaultEnablement(true);
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.before().before().before());
    functionNames_ = defaultNoReturnNames();
}

std::unordered_set<std::string> NoReturnFunctionAnalyzer::defaultNoReturnNames() {
    return {
        "exit", "abort", "ExitProcess", "TerminateProcess",
        "_exit", "_Exit", "quick_exit", "longjmp",
        "siglongjmp", "execve", "execvp", "execvpe",
        "execl", "execlp", "execle", "execv",
        "fexecve", "pthread_exit", "thr_exit",
        "__assert_fail", "__assert", "_wassert",
        "halt", "panic", "bug", "_terminate",
        "cexit", "DoExit", "FatalExit",
        "ExitThread", "exit_thread",
        "raise", "StackOverflow",
        "__cxa_throw", "terminate", "unexpected",
        "__cxa_call_unexpected",
        "Exit", "exit"
    };
}

bool NoReturnFunctionAnalyzer::canAnalyze(Program* program) const {
    return true;
}

bool NoReturnFunctionAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* symTable = program->getSymbolTable();
    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!symTable || !funcMgr || !listing) return false;

    if (monitor) {
        monitor->setMessage("Finding known non-returning functions");
    }

    SymbolIterator symIter = symTable->getAllProgramSymbols(true);
    while (symIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        Symbol* sym = symIter.next();
        if (!sym) continue;

        Address addr = sym->getAddress();
        if (!set.contains(addr)) continue;

        std::string name = sym->getName();
        if (name.empty()) continue;

        size_t startIndex = 0;
        while (startIndex < name.size() && name[startIndex] == '_') {
            ++startIndex;
        }
        if (startIndex > 0) {
            name = name.substr(startIndex);
        }
        if (name.empty()) continue;

        if (functionNames_.find(name) != functionNames_.end()) {
            markNoReturn(program, name, monitor, log);
            continue;
        }

        for (const auto& pattern : wildcardFunctionNames_) {
            if (name.find(pattern) == 0) {
                markNoReturn(program, name, monitor, log);
                break;
            }
        }
    }

    return true;
}

void NoReturnFunctionAnalyzer::markNoReturn(Program* program, const std::string& name,
                                             TaskMonitor* monitor, MessageLog& log) {
    auto* symTable = program->getSymbolTable();
    auto* funcMgr = program->getFunctionManager();

    std::vector<Symbol*> syms = symTable->getGlobalSymbols(name);
    if (syms.empty()) return;

    for (Symbol* sym : syms) {
        if (!sym) continue;
        Address addr = sym->getAddress();

        Function* func = funcMgr->getFunctionAt(addr);
        if (!func) {
            func = funcMgr->createFunction("", addr, AddressSet(addr, addr),
                                            SourceType::ANALYSIS);
        }
        if (!func) {
            log.append("Failed to create function for " + name + " at " + addr.toString());
            continue;
        }

        func->setHasNoReturn(true);

        if (createBookmarksEnabled_) {
            program->getBookmarkManager()->setBookmark(
                addr, "Analysis", "Non-Returning Function Identified");
        }
    }
}

void NoReturnFunctionAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool("Create Analysis Bookmarks", createBookmarksEnabled_,
                         "Create a bookmark for each function marked as non-returning.");
}

void NoReturnFunctionAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption("Create Analysis Bookmarks"))
        createBookmarksEnabled_ = options.getBool("Create Analysis Bookmarks");
}

} // namespace ghidra
