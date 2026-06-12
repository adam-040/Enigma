#include <ghidra/StringsAnalyzer.h>
#include <ghidra/Memory.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/StringDataType.h>
#include <ghidra/Data.h>
#include <ghidra/MemoryBlock.h>
#include <vector>

namespace ghidra {

StringsAnalyzer::StringsAnalyzer()
    : AbstractAnalyzer("ASCII Strings",
                       "Searches for valid strings in undefined memory.",
                       AnalyzerType::BYTE_ANALYZER) {
    setPriority(AnalysisPriority::DATA_ANALYSIS);
    setDefaultEnablement(true);
    setSupportsOneTimeAnalysis(true);
}

bool StringsAnalyzer::canAnalyze(Program* program) const {
    return program != nullptr;
}

bool StringsAnalyzer::added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) {
    if (!program) return false;
    
    auto* memory = program->getMemory();
    auto* listing = program->getListing();
    if (!memory || !listing) return false;

    int minStringLength = 5;

    for (auto* block : memory->getBlocks()) {
        if (!block || !block->isInitialized()) continue;

        Address start = block->getStart();
        Address end = block->getEnd();
        
        Address current = start;
        while (current <= end) {
            if (monitor && monitor->isCancelled()) break;

            if (!listing->isUndefined(current)) {
                current = current.add(1);
                continue;
            }

            int stringLen = 0;
            bool isNullTerminated = false;
            Address testAddr = current;
            
            while (testAddr <= end) {
                uint8_t byteVal;
                if (memory->getBytes(testAddr, &byteVal, 1) != 1) break;
                
                if (byteVal == 0x00) {
                    isNullTerminated = true;
                    stringLen++;
                    break;
                }
                
                // Printable ASCII check
                if (byteVal >= 0x20 && byteVal <= 0x7E) {
                    stringLen++;
                    testAddr = testAddr.add(1);
                } else {
                    break;
                }
            }

            if (isNullTerminated && stringLen > minStringLength) {
                // Ensure all bytes were undefined
                bool allUndefined = true;
                Address checkAddr = current;
                for (int i = 0; i < stringLen; ++i) {
                    if (!listing->isUndefined(checkAddr)) {
                        allUndefined = false;
                        break;
                    }
                    checkAddr = checkAddr.add(1);
                }

                if (allUndefined) {
                    StringDataType* stringType = new StringDataType();
                    Data* data = new Data(program, current, stringType, stringLen);
                    listing->addData(data);
                }
                current = current.add(stringLen);
            } else {
                current = current.add(1);
            }
        }
    }
    
    return true;
}

} // namespace ghidra
