#include <ghidra/WindowsResourceReferenceAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/BookmarkManager.h>
#include <ghidra/Options.h>
#include <ghidra/Msg.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Scalar.h>
#include <algorithm>
#include <sstream>

namespace ghidra {

static const char* OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
static const char* OPTION_DESCRIPTION_CREATE_BOOKMARKS =
    "Select this check box if you want this analyzer to create analysis bookmarks "
    "when items of interest are created/identified by the analyzer.";

static const struct {
    const char* name;
    int paramIndex;
    const char* resourcePrefix;
} KNOWN_RESOURCE_APIS[] = {
    {"AfxMessageBox",       1, "Rsrc_StringTable"},
    {"CreateDialogParamA",  2, "Rsrc_Dialog"},
    {"CreateDialogParamW",  2, "Rsrc_Dialog"},
    {"DialogBoxParamA",     2, "Rsrc_Dialog"},
    {"DialogBoxParamW",     2, "Rsrc_Dialog"},
    {"FindResourceA",       2, "Rsrc_*"},
    {"FindResourceW",       2, "Rsrc_*"},
    {"LoadAcceleratorsA",   2, "Rsrc_Accelerator"},
    {"LoadAcceleratorsW",   2, "Rsrc_Accelerator"},
    {"LoadBitmapA",         2, "Rsrc_Bitmap"},
    {"LoadBitmapW",         2, "Rsrc_Bitmap"},
    {"LoadCursorA",         2, "Rsrc_*"},
    {"LoadCursorW",         2, "Rsrc_*"},
    {"LoadIconA",           2, "Rsrc_GroupIcon"},
    {"LoadIconW",           2, "Rsrc_GroupIcon"},
    {"LoadImageA",          2, "Rsrc_*"},
    {"LoadImageW",          2, "Rsrc_*"},
    {"LoadMenuA",           2, "Rsrc_Menu"},
    {"LoadMenuW",           2, "Rsrc_Menu"},
    {"LoadStringA",         2, "Rsrc_StringTable"},
    {"LoadStringW",         2, "Rsrc_StringTable"},
    {"PlaySoundW",          1, "Rsrc_WAVE"},
};

WindowsResourceReferenceAnalyzer::WindowsResourceReferenceAnalyzer()
    : AbstractAnalyzer("WindowsResourceReference",
                       "Given certain Key windows API calls, tries to create references at the use of windows Resources.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::DATA_TYPE_PROPOGATION);
    setDefaultEnablement(true);
}

bool WindowsResourceReferenceAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    const std::string& format = program->getExecutableFormat();
    return format.find("PE") != std::string::npos ||
           format.find("Portable Executable") != std::string::npos;
}

void WindowsResourceReferenceAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled_,
                         OPTION_DESCRIPTION_CREATE_BOOKMARKS);
}

void WindowsResourceReferenceAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(OPTION_NAME_CREATE_BOOKMARKS)) {
        createBookmarksEnabled_ = options.getBool(OPTION_NAME_CREATE_BOOKMARKS);
    }
}

bool WindowsResourceReferenceAnalyzer::added(Program* program, const AddressSetView& set,
                                              TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    if (monitor) monitor->setMessage("Analyzing Windows resource references...");

    SymbolTable* symTable = program->getSymbolTable();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    ReferenceManager* refMgr = program->getReferenceManager();
    BookmarkManager* bmMgr = program->getBookmarkManager();

    if (!symTable || !listing || !funcMgr || !refMgr) {
        Msg::info(getName(), "Required services unavailable. Skipping.");
        return true;
    }

    // Build sorted instruction list for backwards walking
    std::vector<Instruction*> allInstrs = listing->getInstructions(set);
    std::sort(allInstrs.begin(), allInstrs.end(), [](Instruction* a, Instruction* b) {
        if (!a || !b) return a < b;
        return a->getAddress() < b->getAddress();
    });

    bool foundAny = false;

    for (const auto& api : KNOWN_RESOURCE_APIS) {
        if (monitor && monitor->isCancelled()) break;

        SymbolIterator symIter = symTable->getSymbols(api.name);
        if (!symIter.hasNext()) continue;

        while (symIter.hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            Symbol* sym = symIter.next();
            if (!sym) continue;

            Function* apiFunc = funcMgr->getFunctionAt(sym->getAddress());
            if (!apiFunc) continue;

            std::vector<Reference*> refs = refMgr->getReferencesTo(sym->getAddress());

            for (Reference* ref : refs) {
                if (monitor && monitor->isCancelled()) break;
                if (!ref) continue;

                Address fromAddr = ref->getFromAddress();
                if (!set.contains(fromAddr)) continue;

                Instruction* instr = listing->getInstructionAt(fromAddr);
                if (!instr) continue;

                long long resourceId = findResourceIdImmediate(allInstrs, fromAddr, api.paramIndex);
                if (resourceId < 0) continue;

                std::string resourcePrefix(api.resourcePrefix);
                Address resourceAddr = findResourceAddress(symTable, resourcePrefix, resourceId);
                if (!resourceAddr.isValid()) {
                    if (resourcePrefix == "Rsrc_*") {
                        static const char* WILDCARD_TYPES[] = {
                            "Rsrc_StringTable", "Rsrc_Dialog", "Rsrc_Menu",
                            "Rsrc_GroupIcon", "Rsrc_Bitmap", "Rsrc_Cursor",
                            "Rsrc_Accelerator", "Rsrc_WAVE", "Rsrc_MUI",
                            nullptr
                        };
                        for (int t = 0; WILDCARD_TYPES[t]; t++) {
                            resourceAddr = findResourceAddress(symTable, WILDCARD_TYPES[t],
                                                               resourceId);
                            if (resourceAddr.isValid()) break;
                        }
                    }
                    if (!resourceAddr.isValid()) continue;
                }

                // Create memory reference
                refMgr->addMemoryReference(instr->getAddress(), resourceAddr,
                                           &RefTypes::DATA, SourceType::ANALYSIS, -1);

                if (createBookmarksEnabled_ && bmMgr) {
                    bmMgr->setBookmark(instr->getMinAddress(), "ANALYSIS",
                                       "WindowsResourceReference: " + resourcePrefix +
                                       " ID=0x" + toHexString(resourceId));
                }

                foundAny = true;
            }
        }
    }

    if (monitor) {
        monitor->setMessage(foundAny ? "Windows resource reference analysis complete"
                                     : "No Windows resource references found");
    }

    return true;
}

long long WindowsResourceReferenceAnalyzer::findResourceIdImmediate(
        const std::vector<Instruction*>& sortedInstrs,
        const Address& callAddr, int paramIndex) {
    // Find the CALL instruction in the sorted list
    auto it = std::find_if(sortedInstrs.begin(), sortedInstrs.end(),
        [&callAddr](Instruction* instr) {
            return instr && instr->getAddress() == callAddr;
        });

    if (it == sortedInstrs.end()) return -1;

    int pushesNeeded = paramIndex;

    // Walk backwards from the CALL
    auto cur = it;
    while (cur != sortedInstrs.begin() && pushesNeeded > 0) {
        --cur;
        Instruction* prevInstr = *cur;
        if (!prevInstr) continue;

        std::string mnemonic = prevInstr->getMnemonicString();
        for (auto& c : mnemonic) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        if (mnemonic == "push") {
            pushesNeeded--;
            if (pushesNeeded == 0) {
                auto scalars = prevInstr->getOperandScalars(0);
                if (!scalars.empty() && scalars[0]) {
                    return static_cast<long long>(scalars[0]->getUnsignedValue());
                }
                return -1;
            }
        }
    }

    return -1;
}

Address WindowsResourceReferenceAnalyzer::findResourceAddress(SymbolTable* symTable,
                                                               const std::string& prefix,
                                                               long long resourceId) {
    std::string hexSuffix = toHexString(resourceId);
    std::string exactName = prefix + "_" + hexSuffix;

    SymbolIterator symIter = symTable->getSymbols(exactName);
    if (symIter.hasNext()) {
        Symbol* sym = symIter.next();
        if (sym) return sym->getAddress();
    }

    SymbolIterator allIter = symTable->getSymbols(prefix + "_");
    while (allIter.hasNext()) {
        Symbol* sym = allIter.next();
        if (!sym) continue;
        std::string symName = sym->getName();
        auto pos = symName.rfind('_');
        if (pos != std::string::npos) {
            std::string symHex = symName.substr(pos + 1);
            long long symValue;
            std::stringstream ss;
            ss << std::hex << symHex;
            if (ss >> symValue && symValue == resourceId) {
                return sym->getAddress();
            }
        }
    }

    return Address();
}

std::string WindowsResourceReferenceAnalyzer::toHexString(long long value) const {
    std::stringstream ss;
    ss << std::hex << value;
    return ss.str();
}

} // namespace ghidra
