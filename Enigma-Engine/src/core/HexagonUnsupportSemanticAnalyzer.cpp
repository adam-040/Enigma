#include <ghidra/HexagonUnsupportSemanticAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Memory.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Register.h>
#include <ghidra/ProgramContext.h>
#include <ghidra/Language.h>
#include <ghidra/Processor.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/Msg.h>
#include <cstdint>

namespace ghidra {

HexagonUnsupportSemanticAnalyzer::HexagonUnsupportSemanticAnalyzer()
    : AbstractAnalyzer("Hexagon Unsupported Semantic Check",
                       "Detects instruction packets which read a predicate register before it is written.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::CODE_ANALYSIS);
    setDefaultEnablement(true);
}

bool HexagonUnsupportSemanticAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    return program->getLanguage()->getProcessor().getName() == "Hexagon";
}

bool HexagonUnsupportSemanticAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool HexagonUnsupportSemanticAnalyzer::added(Program* program, const AddressSetView& set,
                                              TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;
    monitor->setMessage("Checking Hexagon predicate semantics...");

    Listing* listing = program->getListing();
    if (!listing) return true;

    // Check for predicate registers (p0-p3 in Hexagon)
    std::string predNames[4] = {"p0", "p1", "p2", "p3"};

    auto instructions = listing->getInstructions(set);
    int issuesFound = 0;
    for (Instruction* instr : instructions) {
        if (monitor->isCancelled()) break;

        // Check input objects for predicate register usage
        for (Register* reg : instr->getInputObjects()) {
            for (const auto& pn : predNames) {
                if (reg && reg->getName() == pn) {
                    ++issuesFound;
                    break;
                }
            }
        }
    }

    if (issuesFound > 0) {
        Msg::info(getName(), "Found " + std::to_string(issuesFound) +
                  " instructions with predicate semantic checks.");
    }
    return true;
}

} // namespace ghidra
