#include <ghidra/PcodeParser.h>
#include <ghidra/SleighLanguage.h>
#include <ghidra/SleighException.h>

namespace ghidra {

PcodeParser::PcodeParser(SleighLanguage* lang, long uniqueBase)
    : language_(lang), uniqueBase_(uniqueBase), nextUnique_(uniqueBase) {}

void PcodeParser::addOperand(const Location& loc, const std::string& name, int index) {}

ConstructTpl* PcodeParser::compilePcode(const std::string& pcodeText,
                                         const std::string& sourceName, int lineNum) {
    nextUnique_ = uniqueBase_ + 0x100;
    return nullptr;
}

} // namespace ghidra
