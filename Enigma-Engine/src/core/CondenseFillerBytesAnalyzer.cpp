#include <ghidra/CondenseFillerBytesAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/Listing.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/AlignmentDataType.h>
#include <ghidra/Data.h>
#include <ghidra/Options.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AddressSetView.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstdint>
#include <sstream>
#include <iomanip>

namespace ghidra {

CondenseFillerBytesAnalyzer::CondenseFillerBytesAnalyzer()
    : AbstractAnalyzer("Condense Filler Bytes",
                       "This analyzer finds filler bytes between functions and collapses them",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::REFERENCE_ANALYSIS.after().after());
    setSupportsOneTimeAnalysis(true);
}

bool CondenseFillerBytesAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    auto* memory = program->getMemory();
    if (!memory) return false;
    auto blocks = memory->getBlocks();
    for (auto* block : blocks) {
        if (block && block->isInitialized()) {
            return true;
        }
    }
    return false;
}

std::string CondenseFillerBytesAnalyzer::determineFillerValue(Program* program) const {
    auto* listing = program->getListing();
    auto* funcMgr = program->getFunctionManager();
    auto* memory = program->getMemory();
    if (!listing || !funcMgr || !memory) return "";

    std::unordered_map<std::string, int> patterns;
    FunctionIterator iter = funcMgr->getFunctions(true);

    while (iter.hasNext()) {
        auto* func = iter.next();
        if (!func) continue;

        Address maxAddr = func->getBody().getMaxAddress();
        Address fillerAddr = maxAddr.next();

        if (!listing->isUndefined(fillerAddr)) continue;

        uint8_t byteVal;
        if (memory->getBytes(fillerAddr, &byteVal, 1) != 1) continue;

        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byteVal);
        std::string pattern = oss.str();

        auto it = patterns.find(pattern);
        if (it != patterns.end()) {
            it->second++;
        } else {
            patterns[pattern] = 1;
        }
    }

    if (patterns.empty()) return "";

    std::string mostFrequent;
    int maxCount = 0;
    for (const auto& pair : patterns) {
        if (pair.second > maxCount) {
            maxCount = pair.second;
            mostFrequent = pair.first;
        }
    }
    return mostFrequent;
}

bool CondenseFillerBytesAnalyzer::added(Program* program, const AddressSetView& set,
                                         TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    auto* listing = program->getListing();
    auto* memory = program->getMemory();
    auto* funcMgr = program->getFunctionManager();
    if (!listing || !memory || !funcMgr) return false;

    if (monitor) monitor->setMessage("Condensing filler bytes...");

    uint8_t fillerByte = 0;
    if (fillerValue_ == "Auto") {
        std::string detected = determineFillerValue(program);
        if (detected.empty()) return false;
        fillerByte = static_cast<uint8_t>(std::stoi(detected, nullptr, 16));
    } else {
        std::string val = fillerValue_;
        if (val.size() >= 2 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
            fillerByte = static_cast<uint8_t>(std::stoi(val, nullptr, 0));
        } else {
            fillerByte = static_cast<uint8_t>(std::stoi(val, nullptr, 16));
        }
    }

    std::vector<uint8_t> testBytes(minBytes_, fillerByte);
    std::vector<uint8_t> programBytes(minBytes_);

    FunctionIterator funcIter = funcMgr->getFunctions(true);
    while (funcIter.hasNext()) {
        if (monitor && monitor->isCancelled()) return false;

        auto* func = funcIter.next();
        if (!func) continue;

        Address maxAddr = func->getBody().getMaxAddress();
        Address fillerAddr = maxAddr.next();

        if (!listing->isUndefined(fillerAddr)) continue;

        int bytesRead = memory->getBytes(fillerAddr, programBytes.data(), minBytes_);
        if (bytesRead != minBytes_) continue;

        bool match = true;
        for (int i = 0; i < minBytes_; i++) {
            if (programBytes[i] != fillerByte) {
                match = false;
                break;
            }
        }
        if (!match) continue;

        int fillerLength = countUndefineds(program, fillerAddr, fillerByte);

        replaceFillerBytes(listing, fillerAddr, fillerLength);
    }

    return true;
}

int CondenseFillerBytesAnalyzer::countUndefineds(Program* program, Address address, uint8_t fillerByte) const {
    int count = 1;
    auto* listing = program->getListing();
    auto* memory = program->getMemory();
    if (!listing || !memory) return count;

    Address current = address.next();
    while (true) {
        if (!listing->isUndefined(current)) break;

        uint8_t byteVal;
        if (memory->getBytes(current, &byteVal, 1) != 1) break;
        if (byteVal != fillerByte) break;

        count++;
        current = current.next();
    }
    return count;
}

void CondenseFillerBytesAnalyzer::replaceFillerBytes(Listing* listing, Address address, int length) {
    if (length <= 0) return;
    AlignmentDataType alignType;
    listing->createData(address, &alignType, length);
}

void CondenseFillerBytesAnalyzer::registerOptions(Options& options, Program* program) {
    options.registerInt("Minimum number of sequential bytes", minBytes_,
                         "Enter the minimum number of sequential bytes to collapse");
    options.registerString("Filler Value", fillerValue_,
                           "Enter filler byte to search for and collapse (Examples:  0, 00, 90, cc).  "
                           "\"Auto\" will make the program determine the value (by greatest count).");
}

void CondenseFillerBytesAnalyzer::optionsChanged(Options& options, Program* program) {
    fillerValue_ = options.getString("Filler Value");
    minBytes_ = options.getInt("Minimum number of sequential bytes");
}

} // namespace ghidra
