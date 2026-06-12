#include <ghidra/CliMetadataTokenAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Instruction.h>
#include <ghidra/Language.h>
#include <ghidra/LanguageDescription.h>
#include <ghidra/LanguageID.h>
#include <ghidra/Scalar.h>
#include <ghidra/RefType.h>
#include <ghidra/SourceType.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/CommentType.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <algorithm>
#include <cctype>
#include <sstream>

namespace ghidra {

CliMetadataTokenAnalyzer::CliMetadataTokenAnalyzer()
    : AbstractAnalyzer("CLI Metadata Token Analyzer",
                       "Takes CLI metadata tokens from their table/index form "
                       "and gives a more useful representation.",
                       AnalyzerType::INSTRUCTION_ANALYZER) {
    setSupportsOneTimeAnalysis(true);
    setPriority(AnalysisPriority::CODE_ANALYSIS);
    setPrototype(true);
}

bool CliMetadataTokenAnalyzer::canAnalyze(Program* program) const {
    return getDefaultEnablement(program);
}

bool CliMetadataTokenAnalyzer::getDefaultEnablement(Program* program) const {
    if (!program || !program->getLanguage()) return false;
    LanguageID langId = program->getLanguage()->getLanguageID();
    std::string idStr = langId.getIdAsString();
    std::transform(idStr.begin(), idStr.end(), idStr.begin(), ::toupper);
    return idStr.find("CLI") != std::string::npos;
}

static bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.size() < suffix.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static bool isObjectModelMnemonic(const std::string& mnem) {
    static const char* OBJECT_MODEL_MNEMONICS[] = {
        "box", "castclass", "cpobj", "initobj", "isinst",
        "ldelem", "ldelema", "ldfld", "ldflda", "ldobj",
        "ldsfld", "ldsflda", "ldtoken", "mkrefany", "newarr",
        "newobj", "refanyval", "sizeof", "stelem", "stfld",
        "stobj", "stsfld", "unbox", "unbox.any"
    };
    for (auto* name : OBJECT_MODEL_MNEMONICS) {
        if (endsWith(mnem, name)) return true;
    }
    return false;
}

bool CliMetadataTokenAnalyzer::added(Program* program, const AddressSetView& set,
                                      TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;

    Listing* listing = program->getListing();
    if (!listing) return false;

    auto instructions = listing->getInstructions(set);
    int processedCount = 0;

    for (Instruction* instr : instructions) {
        if (monitor && monitor->isCancelled()) break;

        const std::string& mnem = instr->getMnemonicString();

        if (endsWith(mnem, "ldstr")) {
            auto scalars = instr->getOperandScalars(0);
            if (!scalars.empty()) {
                Scalar* s = scalars[0];
                uintb token = s->getUnsignedValue();
                std::stringstream ss;
                ss << "String token: 0x" << std::hex << token;
                instr->setComment(ss.str());
                ++processedCount;
            }
        }
        else if (endsWith(mnem, "call") || endsWith(mnem, "jmp") || endsWith(mnem, "callvirt")) {
            auto scalars = instr->getOperandScalars(0);
            if (scalars.size() >= 2) {
                uintb tableIdx = scalars[0]->getUnsignedValue();
                uintb rowIdx = scalars[1]->getUnsignedValue();

                const RefType* refType = &RefTypes::UNCONDITIONAL_CALL;
                if (endsWith(mnem, "jmp")) {
                    refType = &RefTypes::UNCONDITIONAL_JUMP;
                } else if (endsWith(mnem, "callvirt")) {
                    refType = &RefTypes::COMPUTED_CALL;
                }

                    const AddressSpace* defSpace = program->getAddressFactory()->getDefaultAddressSpace();
                if (defSpace) {
                    Address destAddr(const_cast<AddressSpace*>(defSpace), static_cast<int64_t>(rowIdx));
                    instr->addOperandReference(1, destAddr, refType, SourceType::ANALYSIS);
                    std::stringstream ss;
                    ss << "Metadata: table=0x" << std::hex << tableIdx << " row=0x" << rowIdx;
                    instr->setComment(ss.str());
                    ++processedCount;
                }
            }
        }
        else if (isObjectModelMnemonic(mnem)) {
            auto scalars = instr->getOperandScalars(0);
            if (scalars.size() >= 2) {
                uintb tableIdx = scalars[0]->getUnsignedValue();
                uintb rowIdx = scalars[1]->getUnsignedValue();
                std::stringstream ss;
                ss << "Metadata: table=0x" << std::hex << tableIdx << " row=0x" << rowIdx;
                instr->setComment(ss.str());
                ++processedCount;
            }
        }
        else if (endsWith(mnem, "ldftn") || endsWith(mnem, "ldvirtfn") ||
                 endsWith(mnem, "constrained")) {
            auto scalars = instr->getOperandScalars(0);
            if (scalars.size() >= 2) {
                uintb tableIdx = scalars[0]->getUnsignedValue();
                uintb rowIdx = scalars[1]->getUnsignedValue();
                std::stringstream ss;
                ss << "Metadata: table=0x" << std::hex << tableIdx << " row=0x" << rowIdx;
                instr->setComment(ss.str());
                ++processedCount;
            }
        }
    }

    if (processedCount > 0) {
        log.append(getName(), "Processed " + std::to_string(processedCount) +
                   " CLI metadata token instructions");
    }
    return true;
}

} // namespace ghidra
