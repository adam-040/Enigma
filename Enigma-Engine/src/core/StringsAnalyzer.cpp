#include <ghidra/StringsAnalyzer.h>
#include <ghidra/Memory.h>
#include <ghidra/Program.h>
#include <ghidra/Listing.h>
#include <ghidra/StringDataType.h>
#include <ghidra/Data.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/Symbol.h>
#include <ghidra/SymbolIterator.h>
#include <ghidra/ReferenceManager.h>
#include <ghidra/Reference.h>
#include <ghidra/Address.h>
#include <ghidra/SourceType.h>
#include <ghidra/Msg.h>
#include <vector>
#include <string>
#include <algorithm>

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
    auto* symTable = program->getSymbolTable();
    auto* refManager = program->getReferenceManager();
    if (!memory || !listing) return false;

    int minStringLength = 5;

    // Phase 1: Find and define strings in undefined memory
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
                
                if (byteVal >= 0x20 && byteVal <= 0x7E) {
                    stringLen++;
                    testAddr = testAddr.add(1);
                } else {
                    break;
                }
            }

            if (isNullTerminated && stringLen > minStringLength) {
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

    // Phase 2: Find offcut string references
    // Look for references that point into the middle of defined strings
    if (symTable && refManager) {
        int offcutCount = 0;
        auto symIt = symTable->getAllProgramSymbols(false);
        while (symIt.hasNext()) {
            if (monitor && monitor->isCancelled()) break;
            Symbol* sym = symIt.next();
            if (!sym) continue;

            // Check if this symbol has references pointing into its middle
            Address symAddr = sym->getAddress();
            Data* symData = listing->getDataAt(symAddr);
            if (!symData) continue;

            DataType* dt = symData->getDataType();
            if (!dt) continue;

            // Get the string length from the data
            int symLen = symData->getLength();
            if (symLen <= 1) continue;

            // Get the string name for creating offcut labels
            std::string baseName = sym->getName();

            // Check all addresses within this string for references
            for (int offset = 1; offset < symLen; ++offset) {
                Address offcutAddr = symAddr.add(offset);
                if (!refManager->hasReferencesTo(offcutAddr)) continue;

                // This address has references pointing into the string
                int remaining = symLen - offset;

                // Create a label for the offcut reference
                std::string offcutLabel = baseName + "_+" + std::to_string(offset);
                auto existingSyms = symTable->getSymbols(offcutAddr);
                if (existingSyms.empty()) {
                    symTable->createLabel(offcutAddr, offcutLabel, SourceType::ANALYSIS);
                    ++offcutCount;
                }
            }
        }

        if (offcutCount > 0) {
            Msg::info(getName(), "Found " + std::to_string(offcutCount) + " offcut string references");
        }
    }
    
    return true;
}

} // namespace ghidra
