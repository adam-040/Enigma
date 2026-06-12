#pragma once

#include <ghidra/Language.h>
#include <ghidra/LanguageID.h>
#include <ghidra/Address.h>
#include <ghidra/AddressSpace.h>
#include <ghidra/AddressFactory.h>
#include <ghidra/Register.h>
#include <ghidra/Varnode.h>
#include <ghidra/PcodeOp.h>
#include <ghidra/SleighInstructionPrototype.h>
#include <ghidra/AddressSetView.h>
#include <ghidra/AddressSet.h>
#include <ghidra/XmlPullParser.h>
#include <ghidra/Decoder.h>
#include <ghidra/RegisterBuilder.h>
#include <ghidra/UseropSymbol.h>
#include <ghidra/ContextField.h>
#include <ghidra/ContextSymbol.h>
#include <ghidra/SymbolTable.h>
#include <ghidra/DecisionNode.h>
#include <ghidra/SleighLanguageDescription.h>
#include <ghidra/AddressLabelInfo.h>
#include <ghidra/ProgramAddressFactory.h>

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <memory>
#include <optional>

namespace ghidra {

class SleighLanguageDescription;

class SleighLanguage : public Language {
public:
    SleighLanguage(SleighLanguageDescription* description);
    SleighLanguage(SleighLanguageDescription* description, TaskMonitor* monitor);
    ~SleighLanguage() override = default;

    long getUniqueBase() const { return uniqueBase; }
    int getUniqueAllocationMask() const { return uniqueAllocateMask; }
    int numSections() const { return _numSections; }

    std::string toString() const override;
    
    void applyContextSettings(DefaultProgramContext* programContext) override;
    AddressFactory* getAddressFactory() override { return addressFactory; }
    LanguageDescription* getLanguageDescription() override { return description; }
    ParallelInstructionLanguageHelper* getParallelInstructionHelper() override { return nullptr; }
    AddressSpace* getDefaultSpace() override { return default_space; }
    AddressSpace* getDefaultDataSpace() override { return defaultDataSpace; }
    ManualEntry getManualEntry() override { return ManualEntry(); }
    Register* getContextBaseRegister() override;
    std::vector<Register*> getContextRegisters() override;
    std::vector<MemoryBlockDefinition*> getDefaultMemoryBlocks() override;
    Register* getProgramCounter() override { return programCounter; }
    std::vector<AddressLabelInfo> getDefaultSymbols() override { return defaultSymbols; }
    int getInstructionAlignment() override { return alignment; }
    int getMinorVersion() override { return description->getMinorVersion(); }
    LanguageID getLanguageID() override { return description->getLanguageID(); }
    std::string getUserDefinedOpName(int index) override;
    int getNumberOfUserDefinedOpNames() override;
    Processor getProcessor() override { return description->getProcessor(); }
    Register* getRegister(AddressSpace* addrspc, long offset, int size) override;
    Register* getRegister(const std::string& name) override;
    Register* getRegister(Address addr, int size) override;
    std::vector<Register*> getRegisters(Address address) override;
    std::vector<Register*> getRegisters() override;
    std::vector<std::string> getRegisterNames() override;
    std::string getSegmentedSpace() override { return segmentedspace; }
    int getVersion() override { return description->getVersion(); }
    AddressSet getVolatileAddresses() override { return volatileAddresses; }
    bool isVolatile(Address addr) override { return volatileAddresses.contains(addr); }
    bool isBigEndian() override { return description->getEndian() == Endian::BIG; }
    
    InstructionPrototype* parse(MemBuffer* buf, ProcessorContext* context, bool inDelaySlot) override;
    
    void reloadLanguage(TaskMonitor* monitor) override;
    bool supportsPcode() override { return true; }
    
    void addUserOp(const UseropSymbol& sym) { userOps_.push_back(sym); }
    void clearUserOps() { userOps_.clear(); }

private:
    void initialize(bool forceCompile, TaskMonitor* monitor);
    void readInitialDescription();
    void read(XmlPullParser* parser);
    void readRemainingSpecification();
    void decode(Decoder* decoder);
    void parseSpaces(Decoder* decoder);
    void buildAddressSpaceFactory();
    void loadRegisters(RegisterBuilder* builder);
    void setHasMappedRegisters(AddressSpace* space);
    void registerContext(const std::string& name, ContextField* field, RegisterBuilder* builder);
    void registerContext(ContextSymbol* sym, RegisterBuilder* builder);
    void xrefRegisters();

    void buildX86Registers();
    void buildARMRegisters();

    SleighLanguageDescription* description = nullptr;
    AddressFactory* addressFactory = nullptr;
    AddressSpace* defaultDataSpace = nullptr;
    RegisterBuilder* registerBuilder = nullptr;
    Register* programCounter = nullptr;
    std::vector<AddressLabelInfo> defaultSymbols;
    
    long uniqueBase = 0;
    int uniqueAllocateMask = 0;
    int _numSections = 0;
    int alignment = 1;
    int defaultPointerWordSize = 1;
    
    std::string segmentedspace = "";
    std::string segmentType = "";
    AddressSet volatileAddresses;
    
    std::unordered_map<int, SleighInstructionPrototype*> instructProtoMap;
    std::map<std::string, AddressSpace*> spacetable;
    AddressSpace* default_space = nullptr;
    
    SymbolTable* symtab = nullptr;
    DecisionNode* root = nullptr;
    std::vector<UseropSymbol> userOps_;

    // Internal register map and storage
    std::unordered_map<std::string, Register*> registerMap_;
    std::vector<std::unique_ptr<Register>> regOwnedStorage_;
    std::unique_ptr<ProgramAddressFactory> addrFactory_;

    // Address spaces owned by this language
    AddressSpace* ram_ = nullptr;
    AddressSpace* regAddrSpace_ = nullptr;
    AddressSpace* constAddrSpace_ = nullptr;
    AddressSpace* uniqueAddrSpace_ = nullptr;
    AddressSpace* stackAddrSpace_ = nullptr;

    // Context fields
    std::vector<ContextField*> contextFields_;
    std::vector<ContextSymbol*> contextSymbols_;
    bool hasMappedRegisters_ = false;
};

} // namespace ghidra
