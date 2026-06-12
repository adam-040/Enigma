#include <ghidra/JvmSwitchAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Language.h>
#include <ghidra/LanguageID.h>
#include <ghidra/CompilerSpec.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AnalysisPriority.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/Memory.h>
#include <ghidra/Scalar.h>
#include <vector>

namespace ghidra {

JvmSwitchAnalyzer::JvmSwitchAnalyzer()
    : AbstractJavaAnalyzer("JVM Switch Analyzer",
                           "Disassembles jump targets of tableswitch and lookupswitch instructions.",
                           AnalyzerType::INSTRUCTION_ANALYZER) {
    setPriority(AnalysisPriority::DISASSEMBLY);
    setSupportsOneTimeAnalysis(true);
}

bool JvmSwitchAnalyzer::canAnalyze(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    std::string langId = program->getLanguageID().getIdAsString();
    return langId.find("JVM") != std::string::npos || langId.find("jvm") != std::string::npos;
}

bool JvmSwitchAnalyzer::getDefaultEnablement(Program* program) const {
    return canAnalyze(program);
}

bool JvmSwitchAnalyzer::analyze(Program* program, const AddressSetView& set,
                                TaskMonitor* monitor, MessageLog& log) {
    if (monitor) {
        monitor->setMessage(getName() + ": Analyzing switch tables...");
    }

    Listing* listing = program->getListing();
    if (!listing) return true;

    std::vector<Instruction*> allInstructions = listing->getInstructions(set);
    int tableSwitchCount = 0;
    int lookupSwitchCount = 0;

    for (Instruction* instr : allInstructions) {
        if (monitor && monitor->isCancelled()) return false;

        const std::string& mnemonic = instr->getMnemonicString();

        if (mnemonic == "tableswitch") {
            tableSwitchCount++;
            if (monitor) {
                monitor->setMessage(getName() + ": Processing tableswitch at " +
                                    instr->getAddress().toString());
            }

            std::vector<Scalar*> scalars = instr->getOperandScalars(0);
            if (scalars.size() >= 3) {
                int64_t defaultOffset = scalars[0]->getSignedValue();
                Address defaultAddr = instr->getAddress().add(defaultOffset);
                program->getReferenceManager()->addMemoryReference(
                    instr->getAddress(), defaultAddr,
                    &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, 0);

                uintb low = scalars[1]->getUnsignedValue();
                uintb high = scalars[2]->getUnsignedValue();

                Address pos = instr->getAddress().add(instr->getLength());
                for (uintb i = low; i <= high; i++) {
                    uint8_t buf[4];
                    if (program->getMemory()->getBytes(pos, buf, 4) == 4) {
                        int32_t offset = (static_cast<int32_t>(buf[0]) << 24) |
                                         (static_cast<int32_t>(buf[1]) << 16) |
                                         (static_cast<int32_t>(buf[2]) << 8) |
                                         (static_cast<int32_t>(buf[3]));
                        Address caseAddr = instr->getAddress().add(offset);
                        program->getReferenceManager()->addMemoryReference(
                            instr->getAddress(), caseAddr,
                            &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, 0);
                        pos = pos.add(4);
                    }
                }
            }
        }
        else if (mnemonic == "lookupswitch") {
            lookupSwitchCount++;
            if (monitor) {
                monitor->setMessage(getName() + ": Processing lookupswitch at " +
                                    instr->getAddress().toString());
            }

            std::vector<Scalar*> scalars = instr->getOperandScalars(0);
            if (scalars.size() >= 2) {
                int64_t defaultOffset = scalars[0]->getSignedValue();
                Address defaultAddr = instr->getAddress().add(defaultOffset);
                program->getReferenceManager()->addMemoryReference(
                    instr->getAddress(), defaultAddr,
                    &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, 0);

                uintb npairs = scalars[1]->getUnsignedValue();

                Address pos = instr->getAddress().add(instr->getLength());
                for (uintb i = 0; i < npairs; i++) {
                    uint8_t buf[8];
                    if (program->getMemory()->getBytes(pos, buf, 8) == 8) {
                        int32_t offset = (static_cast<int32_t>(buf[4]) << 24) |
                                         (static_cast<int32_t>(buf[5]) << 16) |
                                         (static_cast<int32_t>(buf[6]) << 8) |
                                         (static_cast<int32_t>(buf[7]));
                        Address caseAddr = instr->getAddress().add(offset);
                        program->getReferenceManager()->addMemoryReference(
                            instr->getAddress(), caseAddr,
                            &RefTypes::COMPUTED_JUMP, SourceType::ANALYSIS, 0);
                        pos = pos.add(8);
                    }
                }
            }
        }
    }

    if (monitor) {
        monitor->setMessage(getName() + ": Found " + std::to_string(tableSwitchCount) +
                            " tableswitch, " + std::to_string(lookupSwitchCount) +
                            " lookupswitch instructions");
    }

    return true;
}

} // namespace ghidra
