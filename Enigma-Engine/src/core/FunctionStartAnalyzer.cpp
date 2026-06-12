#include <ghidra/FunctionStartAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/AddressSet.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <algorithm>
#include <cstdint>
#include <vector>

namespace ghidra {

static std::vector<std::vector<uint8_t>> getProloguePatterns(const std::string& arch) {
    std::vector<std::vector<uint8_t>> patterns;
    if (arch == "x86") {
        patterns.push_back({0x55, 0x89, 0xE5});
        patterns.push_back({0x55, 0x8B, 0xEC});
        patterns.push_back({0x55, 0x48, 0x89, 0xE5});
        patterns.push_back({0x55, 0x48, 0x8B, 0xEC});
        patterns.push_back({0x53, 0x89, 0xE5});
        patterns.push_back({0x57, 0x56, 0x53});
    } else if (arch == "ARM") {
        patterns.push_back({0x80, 0xB5});
        patterns.push_back({0xF0, 0xB5});
        patterns.push_back({0x10, 0xB5});
        patterns.push_back({0x2D, 0xE9});
        patterns.push_back({0x00, 0x48});  // ldr r0, [pc, #0]
    } else if (arch == "MIPS") {
        patterns.push_back({0x27, 0xBD});  // addiu sp, sp, ...
        patterns.push_back({0x3C, 0x1C});  // lui gp, ...
    } else if (arch == "PowerPC") {
        patterns.push_back({0x94, 0x21});  // stwu r1, ...
        patterns.push_back({0x7C, 0x08});  // mflr r0
    }
    return patterns;
}

static std::string languageToArchShort(const std::string& langId) {
    std::string lower = langId;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("x86") != std::string::npos || lower.find("i386") != std::string::npos)
        return "x86";
    if (lower.find("arm") != std::string::npos)
        return "ARM";
    if (lower.find("mips") != std::string::npos)
        return "MIPS";
    if (lower.find("ppc") != std::string::npos || lower.find("powerpc") != std::string::npos)
        return "PowerPC";
    return "";
}

static int findFunctionStarts(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, int maxPerPass) {
    Memory* memory = program->getMemory();
    Listing* listing = program->getListing();
    FunctionManager* funcMgr = program->getFunctionManager();
    if (!memory || !listing || !funcMgr) return 0;

    Language* lang = program->getLanguage();
    if (!lang) return 0;
    std::string arch = languageToArchShort(lang->getLanguageID().getIdAsString());
    auto patterns = getProloguePatterns(arch);
    if (patterns.empty()) return 0;

    int found = 0;
    AddressRangeIterator* iter = set.getAddressRanges(true);
    while (iter->hasNext() && !monitor->isCancelled() && found < maxPerPass) {
        const AddressRange& range = iter->next();
        Address addr = range.getMinAddress();
        while (addr <= range.getMaxAddress() && !monitor->isCancelled() && found < maxPerPass) {
            if (!listing->isUndefined(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }
            if (funcMgr->getFunctionContaining(addr)) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            MemoryBlock* block = memory->getBlock(addr);
            if (!block || !block->isExecute() || !block->isInitialized()) {
                try { addr = addr.add(1); } catch (...) { break; }
                continue;
            }

            for (const auto& pattern : patterns) {
                if (monitor->isCancelled()) break;
                if (static_cast<int64_t>(addr.getOffset()) + static_cast<int64_t>(pattern.size()) > range.getMaxAddress().getOffset() + 1)
                    continue;

                uint8_t buf[8];
                int read = block->getBytes(addr, buf, static_cast<int>(pattern.size()));
                if (read != static_cast<int>(pattern.size())) continue;

                bool match = true;
                for (size_t i = 0; i < pattern.size(); ++i) {
                    if (buf[i] != pattern[i]) { match = false; break; }
                }
                if (!match) continue;

                if (!funcMgr->getFunctionAt(addr) && !funcMgr->getFunctionContaining(addr)) {
                    AddressSet body(addr, addr);
                    funcMgr->createFunction("func_start_" + std::to_string(addr.getOffset()),
                                            addr, body, SourceType::ANALYSIS);
                    ++found;
                }
                break;
            }

            try { addr = addr.add(1); } catch (...) { break; }
        }
    }
    return found;
}

FunctionStartAnalyzer::FunctionStartAnalyzer()
    : AbstractAnalyzer("Function Start Search",
                       "Finds generic function starts using byte patterns.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::FORMAT_ANALYSIS.after());
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool FunctionStartAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool FunctionStartAnalyzer::added(Program* program, const AddressSetView& set,
                                   TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Searching for function starts by byte pattern...");
    int count = findFunctionStarts(program, set, monitor, 500);
    if (count > 0) {
        Msg::info(getName(), "Found " + std::to_string(count) + " function starts by pattern.");
    }
    return true;
}

} // namespace ghidra
