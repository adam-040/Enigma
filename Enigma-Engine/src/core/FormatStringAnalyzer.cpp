#include <ghidra/FormatStringAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/DecompilerAdapter.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/Msg.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

namespace ghidra {

static const char* OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks";
static const char* OPTION_DESCRIPTION_CREATE_BOOKMARKS =
    "Select this check box if you want this analyzer to create analysis bookmarks "
    "when items of interest are created/identified by the analyzer.";

static bool isPrintfLike(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) lower += static_cast<char>(std::tolower(c));
    return lower == "printf" || lower == "sprintf" || lower == "snprintf" ||
           lower == "fprintf" || lower == "dprintf" ||
           lower == "syslog" || lower == "vsyslog" ||
           lower == "__mingw_printf" || lower == "__mingw_sprintf" || lower == "__mingw_snprintf" ||
           lower == "__mingw_fprintf" || lower == "__mingw_vfprintf" ||
           lower == "__mingw_vsprintf" || lower == "__mingw_vsnprintf";
}

static bool isScanfLike(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (char c : name) lower += static_cast<char>(std::tolower(c));
    return lower == "scanf" || lower == "sscanf" || lower == "fscanf" ||
           lower == "vscanf" || lower == "vsscanf" || lower == "vfscanf" ||
           lower == "__mingw_scanf" || lower == "__mingw_sscanf" || lower == "__mingw_fscanf";
}

static int countFormatArgs(const std::string& fmt) {
    int count = 0;
    bool inPercent = false;
    for (size_t i = 0; i < fmt.size(); ++i) {
        char c = fmt[i];
        if (c == '%' && (i + 1 < fmt.size() && fmt[i + 1] != '%')) {
            inPercent = true;
        } else if (inPercent) {
            if (c == 'd' || c == 'i' || c == 'o' || c == 'u' ||
                c == 'x' || c == 'X' || c == 'f' || c == 'F' ||
                c == 'e' || c == 'E' || c == 'g' || c == 'G' ||
                c == 'a' || c == 'A' || c == 'c' || c == 's' ||
                c == 'p' || c == 'n' || c == 'z' || c == 't' ||
                c == 'j') {
                ++count;
                inPercent = false;
            } else if (c == 'l' || c == 'h' || c == 'L' || c == 'w' ||
                       c == 'I' || c == 'z' || c == 't' || c == 'j') {
            } else if (std::isdigit(c) || c == '.' || c == '-' || c == '+' ||
                       c == ' ' || c == '#' || c == '*') {
            } else {
                inPercent = false;
            }
        }
    }
    return count;
}

FormatStringAnalyzer::FormatStringAnalyzer()
    : AbstractAnalyzer("Variadic Function Signature Override",
                       "Detects variadic function calls in the bodies of each function that intersect the "
                       "current selection and parses their format string arguments to infer the correct "
                       "signatures. Currently, this analyzer only supports printf, scanf, and their variants "
                       "(e.g., snprintf, fscanf). If the current selection is empty, it searches through "
                       "every function. Once the correct signatures are inferred, they are overridden.",
                       AnalyzerType::FUNCTION_SIGNATURES_ANALYZER) {
    setSupportsOneTimeAnalysis();
    setPriority(AnalysisPriority::LOW_PRIORITY);
    setDefaultEnablement(false);
    setPrototype(true);
}

bool FormatStringAnalyzer::canAnalyze(Program* program) const {
    return true;
}

void FormatStringAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerBool(OPTION_NAME_CREATE_BOOKMARKS, createBookmarksEnabled_,
                         OPTION_DESCRIPTION_CREATE_BOOKMARKS);
}

void FormatStringAnalyzer::optionsChanged(Options& options, Program* program) {
    if (options.hasOption(OPTION_NAME_CREATE_BOOKMARKS)) {
        createBookmarksEnabled_ = options.getBool(OPTION_NAME_CREATE_BOOKMARKS);
    }
}

bool FormatStringAnalyzer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* funcMgr = program->getFunctionManager();
    auto* listing = program->getListing();
    if (!funcMgr || !listing) return false;

    auto adapter = createDecompilerAdapter();
    auto* programDB = dynamic_cast<ProgramDB*>(program);
    if (!adapter || !programDB || !adapter->initialize(programDB)) {
        Msg::info(getName(), "Decompiler not available for format string analysis.");
        return true;
    }

    FunctionIterator funcIter = funcMgr->getFunctions(set);
    if (monitor) monitor->initialize(static_cast<int>(funcIter.remaining()));

    int count = 0;
    int found = 0;

    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) break;
        if (monitor) monitor->setProgress(++count);

        Function* func = funcIter.next();
        if (!func) continue;

        monitor->setMessage("Analyzing: " + func->getName());
        auto decompRes = adapter->decompileFunction(func, 30);

        if (!decompRes.success) continue;

        const std::string& cCode = decompRes.cCode;
        std::vector<std::string> lines;
        size_t pos = 0;
        while (pos < cCode.size()) {
            size_t nl = cCode.find('\n', pos);
            if (nl == std::string::npos) {
                lines.push_back(cCode.substr(pos));
                break;
            }
            lines.push_back(cCode.substr(pos, nl - pos));
            pos = nl + 1;
        }

        for (const auto& line : lines) {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t"));
            if (trimmed.empty()) continue;

            static const char* knownFuncs[] = {
                "printf", "sprintf", "snprintf", "fprintf", "dprintf",
                "scanf", "sscanf", "fscanf", "syslog", "vsyslog"
            };

            for (const char* knownFunc : knownFuncs) {
                size_t callPos = trimmed.find(knownFunc);
                if (callPos == std::string::npos) continue;

                size_t paren = trimmed.find('(', callPos);
                if (paren == std::string::npos) continue;

                std::string args = trimmed.substr(paren + 1);
                size_t endParen = args.rfind(')');
                if (endParen != std::string::npos)
                    args = args.substr(0, endParen);

                size_t quoteStart = args.find('"');
                if (quoteStart == std::string::npos) continue;

                size_t quoteEnd = args.find('"', quoteStart + 1);
                if (quoteEnd == std::string::npos) continue;

                std::string formatStr = args.substr(quoteStart + 1, quoteEnd - quoteStart - 1);
                int numArgs = countFormatArgs(formatStr);

                if (numArgs > 0 && createBookmarksEnabled_) {
                    Msg::info(getName(), func->getName() + ": " + knownFunc +
                              " with " + std::to_string(numArgs) + " args");
                    ++found;
                }
                break;
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(found) +
                            " variadic call sites");
    }

    return true;
}

} // namespace ghidra
