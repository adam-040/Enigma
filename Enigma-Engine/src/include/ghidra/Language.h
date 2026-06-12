#pragma once

#include <ghidra/LanguageID.h>
#include <ghidra/Processor.h>
#include <ghidra/Address.h>
#include <ghidra/Endian.h>
#include <ghidra/ManualEntry.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressLabelInfo.h>

#include <string>
#include <vector>

namespace ghidra {

class AddressFactory;
class AddressSpace;
class Register;
class MemBuffer;
class TaskMonitor;
class MemoryBlockDefinition;
class LanguageDescription;
class ParallelInstructionLanguageHelper;
class InstructionPrototype;
class DefaultProgramContext;
class ProcessorContext;

class Language {
public:
    virtual ~Language() = default;

    virtual LanguageID getLanguageID() = 0;
    virtual LanguageDescription* getLanguageDescription() = 0;
    virtual ParallelInstructionLanguageHelper* getParallelInstructionHelper() = 0;
    virtual Processor getProcessor() = 0;
    virtual int getVersion() = 0;
    virtual int getMinorVersion() = 0;
    virtual AddressFactory* getAddressFactory() = 0;
    virtual AddressSpace* getDefaultSpace() = 0;
    virtual AddressSpace* getDefaultDataSpace() = 0;
    virtual bool isBigEndian() = 0;
    virtual int getInstructionAlignment() = 0;
    virtual bool supportsPcode() = 0;
    virtual bool isVolatile(Address addr) = 0;
    virtual InstructionPrototype* parse(MemBuffer* buf, ProcessorContext* context, bool inDelaySlot) = 0;
    virtual int getNumberOfUserDefinedOpNames() = 0;
    virtual std::string getUserDefinedOpName(int index) = 0;
    virtual std::vector<Register*> getRegisters(Address address) = 0;
    virtual Register* getRegister(AddressSpace* addrspc, long offset, int size) = 0;
    virtual std::vector<Register*> getRegisters() = 0;
    virtual std::vector<std::string> getRegisterNames() = 0;
    virtual Register* getRegister(const std::string& name) = 0;
    virtual Register* getRegister(Address addr, int size) = 0;
    virtual Register* getProgramCounter() = 0;
    virtual Register* getContextBaseRegister() = 0;
    virtual std::vector<Register*> getContextRegisters() = 0;
    virtual std::vector<MemoryBlockDefinition*> getDefaultMemoryBlocks() = 0;
    virtual std::vector<AddressLabelInfo> getDefaultSymbols() = 0;
    virtual std::string getSegmentedSpace() = 0;
    virtual AddressSet getVolatileAddresses() = 0;
    virtual void applyContextSettings(DefaultProgramContext* ctx) = 0;
    virtual void reloadLanguage(TaskMonitor* monitor) = 0;
    virtual std::string toString() const = 0;
    virtual ManualEntry getManualEntry() = 0;
};

} // namespace ghidra
