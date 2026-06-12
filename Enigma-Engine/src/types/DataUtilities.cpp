#include <ghidra/DataUtilities.h>
#include <ghidra/Data.h>
#include <ghidra/Listing.h>
#include <ghidra/Undefined.h>
#include <ghidra/AddressSet.h>
#include <ghidra/DataIterator.h>
#include <ghidra/InstructionIterator.h>
#include <ghidra/Instruction.h>
#include <ghidra/Memory.h>
#include <ghidra/MemoryBlock.h>
#include <ghidra/CodeUnit.h>
#include <cctype>

namespace ghidra {

bool DataUtilities::isValidDataTypeName(const std::string& name) {
    if (name.empty() || name.find_first_not_of(" \t\n\r") == std::string::npos) {
        return false;
    }

    for (char c : name) {
        // Disallow control characters
        if (std::iscntrl(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

Address DataUtilities::findFirstConflictingAddress(Program* program, const Address& addr, int length, bool ignoreUndefinedData) {
    AddressSet addrSet(addr, addr.addWrap(length - 1));
    std::vector<Data*> definedDataIter = program->getListing()->getData(addrSet);
    Data* data = nullptr;
    for (Data* d : definedDataIter) {
        if (!ignoreUndefinedData || !Undefined::isUndefined(d->getDataType())) {
            data = d;
            break;
        }
    }
    std::vector<Instruction*> instructionIter = program->getListing()->getInstructions(addrSet);
    Instruction* instruction = !instructionIter.empty() ? instructionIter.front() : nullptr;
    
    if (data == nullptr && instruction == nullptr) {
        return Address::NO_ADDRESS;
    }
    if (data == nullptr) {
        return instruction->getAddress();
    }
    if (instruction == nullptr) {
        return data->getAddress();
    }
    Address dataAddr = data->getAddress();
    Address instructionAddr = instruction->getAddress();
    if (dataAddr < instructionAddr) {
        return dataAddr;
    }
    return instructionAddr;
}

bool DataUtilities::isUndefinedRange(Program* program, const Address& startAddress, const Address& endAddress) {
    MemoryBlock* block = program->getMemory()->getBlock(startAddress);
    // start and end address must be in the same block of memory.
    if (block == nullptr || !block->contains(endAddress)) {
        return false;
    }
    if (startAddress > endAddress) {
        return false; // start shouldn't be after end.
    }
    Listing* listing = program->getListing();
    Data* data = listing->getDataContaining(startAddress);
    if (data == nullptr || !Undefined::isUndefined(data->getDataType())) {
        return false; // Instruction or Defined Data at startAddress.
    }
    Address maxAddress = data->getMaxAddress();
    while (maxAddress < endAddress) {
        // Enigma Engine offline Listing does not have getDefinedCodeUnitAfter.
        // We will just check the code unit after maxAddress.
        CodeUnit* codeUnit = nullptr;
        Instruction* instr = listing->getInstructionAfter(maxAddress);
        Data* nextData = listing->getDataContaining(maxAddress.addWrap(1));
        if (instr && nextData) {
            codeUnit = (instr->getAddress() < nextData->getAddress()) ? static_cast<CodeUnit*>(instr) : static_cast<CodeUnit*>(nextData);
        } else if (instr) {
            codeUnit = instr;
        } else if (nextData) {
            codeUnit = nextData;
        }

        if (codeUnit == nullptr) {
            return true; // No more instructions or Defined Data.
        }
        Address minAddress = codeUnit->getAddress();
        if (minAddress > endAddress) {
            return true; // Beyond endAddress so all are undefined.
        }
        Data* dataUnit = dynamic_cast<Data*>(codeUnit);
        if (dataUnit == nullptr || !Undefined::isUndefined(dataUnit->getDataType())) {
            return false; // Instruction or Defined Data in range.
        }
        maxAddress = codeUnit->getMaxAddress();
    }
    return true; // Got to endAddress with only undefined.
}

} // namespace ghidra
