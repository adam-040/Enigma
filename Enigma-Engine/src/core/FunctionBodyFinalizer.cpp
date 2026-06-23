#include <ghidra/FunctionBodyFinalizer.h>
#include <ghidra/Program.h>
#include <ghidra/ProgramDB.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/FunctionManager.h>
#include <ghidra/Function.h>
#include <ghidra/FunctionIterator.h>
#include <ghidra/AddressSet.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>

#include <string>
#include <vector>
#include <algorithm>
#include <cstdint>

namespace ghidra {

FunctionBodyFinalizer::FunctionBodyFinalizer()
    : AbstractAnalyzer(
          "Function Body Finalizer",
          "Extends degenerate function bodies (<=2 bytes) to their real end "
          "by walking existing instructions until RET/JMP/INT3/next function boundary.",
          AnalyzerType::FUNCTION_ANALYZER) {
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::FUNCTION_ANALYSIS.after());
}

bool FunctionBodyFinalizer::canAnalyze(Program* program) const {
    return program != nullptr;
}

static bool isTerminator(const std::string& mn) {
    return mn == "ret" || mn == "retn" || mn == "retf"
        || mn == "int3" || mn == "hlt"
        || mn == "jmp" || mn == "ljmp" || mn == "jmps"
        || mn == "ud2";
}

bool FunctionBodyFinalizer::added(Program* program, const AddressSetView& set,
                                  TaskMonitor* monitor, MessageLog& log)
{
    if (!program) return false;

    FunctionManager* funcMgr = program->getFunctionManager();
    Listing* listing = program->getListing();
    AddressFactory* af = program->getAddressFactory();
    if (!funcMgr || !listing || !af) return false;

    if (monitor) monitor->setMessage(getName() + ": Starting");

    std::vector<Function*> allFuncs;
    {
        FunctionIterator fit = funcMgr->getFunctions(true);
        while (fit.hasNext()) {
            Function* f = fit.next();
            if (f) allFuncs.push_back(f);
        }
    }

    if (allFuncs.empty()) {
        if (monitor) monitor->setMessage(getName() + ": No functions found");
        return true;
    }

    std::vector<uint64_t> funcEntries;
    for (Function* f : allFuncs)
        funcEntries.push_back(f->getEntryPoint().getOffset());
    std::sort(funcEntries.begin(), funcEntries.end());

    int extended = 0;
    int skippedLarge = 0;
    int noInstr = 0;
    int skippedExisting = 0;

    for (Function* func : allFuncs) {
        if (monitor && monitor->isCancelled()) break;

        uint64_t entry = func->getEntryPoint().getOffset();

        const AddressSet& body = func->getBody();
        uint64_t bodyStart = body.getMinAddress().isValid() ? body.getMinAddress().getOffset() : entry;
        uint64_t bodyEnd = body.getMaxAddress().isValid() ? body.getMaxAddress().getOffset() : entry;
        uint64_t bodySize = (bodyEnd >= bodyStart) ? (bodyEnd - bodyStart + 1) : 0;

        if (bodySize > 2 && bodyStart == entry) {
            skippedLarge++;
            continue;
        }

        Address entryAddr = af->oldGetAddressFromLong(entry);
        Instruction* inst = listing->getInstructionAt(entryAddr);
        if (!inst) {
            if (bodySize <= 2) {
                Msg::debug(getName(), "Small body func (no instr): 0x" + std::to_string(entry) +
                           " size=" + std::to_string(bodySize) +
                           " name=" + func->getName());
            }
            noInstr++;
            continue;
        }

        uint64_t maxAddr = entry + kMaxScanBytes;
        auto nextIt = std::upper_bound(funcEntries.begin(), funcEntries.end(), entry);
        if (nextIt != funcEntries.end() && *nextIt > entry && *nextIt - 1 < maxAddr)
            maxAddr = *nextIt - 1;

        if (bodySize <= 2) {
            Msg::debug(getName(), "Small body func (extending): 0x" + std::to_string(entry) +
                       " size=" + std::to_string(bodySize) +
                       " name=" + func->getName() +
                       " maxAddr=0x" + std::to_string(maxAddr));
        }

        Instruction* lastInst = inst;
        uint64_t lastAddr = entry;
        bool foundTerminator = false;

        while (inst) {
            uint64_t instAddr = inst->getAddress().getOffset();
            uint64_t instEnd = instAddr + inst->getLength() - 1;

            if (instAddr > maxAddr) break;

            lastInst = inst;
            lastAddr = instEnd;

            if (isTerminator(inst->getMnemonicString())) {
                foundTerminator = true;
                break;
            }

            Address nextAddr = af->oldGetAddressFromLong(instAddr + inst->getLength());
            inst = listing->getInstructionAt(nextAddr);
            if (!inst) {
                inst = listing->getInstructionAfter(nextAddr);
                if (inst && inst->getAddress().getOffset() > maxAddr)
                    break;
            }
        }

        uint64_t realEnd = lastAddr;
        uint64_t newSize = realEnd - entry + 1;

        if (newSize <= bodySize) {
            skippedExisting++;
            continue;
        }

        AddressSet newBody(entryAddr, af->oldGetAddressFromLong(realEnd));

        SourceType src = func->getSource();
        std::string name = func->getName();
        uint64_t entryVal = entry;

        if (!funcMgr->removeFunction(func->getEntryPoint())) {
            log.append(getName(), "Failed to remove function at " + std::to_string(entryVal));
            continue;
        }

        try {
            funcMgr->createFunction(name, entryAddr, newBody, src);
            extended++;
            Msg::debug(getName(), "Extended 0x" + std::to_string(entryVal) +
                       " from " + std::to_string(bodySize) + " to " + std::to_string(newSize) +
                       " bytes (t=" + (foundTerminator ? "1" : "0") + ")");
        } catch (const std::exception& e) {
            log.append(getName(), "Failed to re-create function at 0x" +
                       std::to_string(entryVal) + ": " + e.what());
            funcMgr->createFunction(name, entryAddr,
                                    AddressSet(entryAddr, entryAddr),
                                    SourceType::ANALYSIS);
        }
    }

    Msg::info(getName(), "Complete: extended " + std::to_string(extended) +
              " large=" + std::to_string(skippedLarge) +
              " noInstr=" + std::to_string(noInstr) +
              " skipped=" + std::to_string(skippedExisting));
    if (monitor) monitor->setMessage(getName() + ": Done (" + std::to_string(extended) + " extended)");
    return true;
}

} // namespace ghidra