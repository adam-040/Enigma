#include <ghidra/RustStringAnalyzer.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/Data.h>
#include <ghidra/StringDataType.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/TaskMonitor.h>
#include <ghidra/MessageLog.h>
#include <ghidra/AddressSet.h>

namespace ghidra {

RustStringAnalyzer::RustStringAnalyzer()
    : AbstractAnalyzer("Rust String Analyzer",
                       "Analyzer to split rust static strings into slices",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::LOW_PRIORITY);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool RustStringAnalyzer::canAnalyze(Program* program) const {
    if (!program) return false;
    return program->getCompiler().find("rustc") != std::string::npos;
}

bool RustStringAnalyzer::added(Program* program, const AddressSetView& set,
                               TaskMonitor* monitor, MessageLog& log) {
    if (!program || !monitor) return false;

    Listing* listing = program->getListing();
    if (!listing) return false;

    AddressSet programSet(program->getMinAddress(), program->getMaxAddress());
    std::vector<Data*> allData = listing->getData(programSet);

    for (Data* data : allData) {
        if (monitor->isCancelled()) break;
        if (!data || !data->isDefined()) continue;
        if (!data->isString() && !data->isUnicode()) continue;

        Address start = data->getAddress();
        int length = data->getLength();

        int maxStringLen = getMaxStringLength(program, start, length);
        if (maxStringLen <= 0 || maxStringLen == length) continue;

        recurseString(program, start, length);
    }

    return true;
}

int RustStringAnalyzer::getMaxStringLength(Program* program, const Address& address,
                                           int maxLen) const {
    ReferenceManager* refMgr = program->getReferenceManager();
    if (!refMgr) return -1;

    for (int i = 1; i <= maxLen; i++) {
        if (refMgr->hasReferencesTo(address.add(i))) {
            return i;
        }
    }

    return -1;
}

void RustStringAnalyzer::recurseString(Program* program, const Address& start, int maxLen) {
    int newLength = getMaxStringLength(program, start, maxLen);
    if (newLength <= 0) return;

    Listing* listing = program->getListing();
    if (!listing) return;

    Data* existing = listing->getDataAt(start);
    if (existing) {
        listing->removeData(start);
    }

    Data* newData = listing->createData(start, &StringDataType::dataType(), newLength);
    if (!newData) return;

    if (newLength < maxLen) {
        recurseString(program, start.add(newLength), maxLen - newLength);
    }
}

} // namespace ghidra
