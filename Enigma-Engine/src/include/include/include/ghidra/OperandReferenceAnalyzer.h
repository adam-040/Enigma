#pragma once

#include <ghidra/AbstractAnalyzer.h>

namespace ghidra {

class OperandReferenceAnalyzer : public AbstractAnalyzer {
public:
    OperandReferenceAnalyzer();
    OperandReferenceAnalyzer(const std::string& name, const std::string& description,
                              AnalyzerType type);

    bool canAnalyze(Program* program) const override;
    bool added(Program* program, const AddressSetView& set, TaskMonitor* monitor, MessageLog& log) override;
    bool getDefaultEnablement(Program* program) const override;
    void registerOptions(Options& options, Program* program) override;
    void optionsChanged(Options& options, Program* program) override;

    // Option names
    static constexpr const char* OPT_NAME_ASCII = "Ascii String References";
    static constexpr const char* OPT_NAME_UNICODE = "Unicode String References";
    static constexpr const char* OPT_NAME_ALIGN_STRINGS = "Align End of Strings";
    static constexpr const char* OPT_NAME_MIN_STRING_LENGTH = "Minimum String Length";
    static constexpr const char* OPT_NAME_POINTER = "References to Pointers";
    static constexpr const char* OPT_NAME_RELOCATION_GUIDE = "Relocation Table Guide";
    static constexpr const char* OPT_NAME_SUBROUTINE = "Subroutine References";
    static constexpr const char* OPT_NAME_ADDRESS_TABLE = "Create Address Tables";
    static constexpr const char* OPT_NAME_SWITCH = "Switch Table References";
    static constexpr const char* OPT_NAME_SWITCH_ALIGNMENT = "Address Table Alignment";
    static constexpr const char* OPT_NAME_MINIMUM_TABLE_SIZE = "Address Table Minimum Size";
    static constexpr const char* OPT_NAME_RESPECT_EXECUTE = "Respect Execute Flag";

    // Accessors for configuration
    bool isAsciiEnabled() const { return asciiEnabled_; }
    bool isUnicodeEnabled() const { return unicodeEnabled_; }
    bool isPointerEnabled() const { return pointerEnabled_; }
    bool isSubroutinesEnabled() const { return subroutinesEnabled_; }
    bool isAddressTablesEnabled() const { return addressTablesEnabled_; }
    bool isSwitchTableEnabled() const { return switchTableEnabled_; }

protected:
    // String detection - public for test access
    int getStringLength(Memory* memory, const Address& startAddress, int stringAlignment);
    int getWStrLen(Memory* memory, const Address& addr);
    int checkAnsiString(Memory* memory, const Address& addr);
    int checkUnicodeString(Memory* memory, const Address& addr);

    bool clearAllUndefined(Program* program, const Address& start, int lenBytes);
    bool desiredDataMemoryContainsReference(Program* program, const Address& rangeStart, int rangeLength);
    AddressSet getExecuteSet(Memory* memory);
    bool hasDataAccessReferences(Program* program, const Address& target);
    bool isValidRelocationAddress(Program* program, const Address& target);
    bool isFunctionPointer(Listing* listing, const Address& fromAddr);
    bool shouldBeValidFunction(Program* program, Instruction* targetInstr);
    bool checkForExternalJump(Program* program, Reference* reference, TaskMonitor* monitor);

    // Option defaults
    bool asciiEnabled_ = true;
    bool unicodeEnabled_ = true;
    bool alignStringsEnabled_ = false;
    int minStringLength_ = 5;
    bool pointerEnabled_ = true;
    bool relocationGuideEnabled_ = true;
    bool subroutinesEnabled_ = true;
    bool addressTablesEnabled_ = true;
    int minimumAddressTableSize_ = 3;
    bool switchTableEnabled_ = false;
    int switchTableAlignment_ = 1;
    int processorAlignment_ = 1;
    bool respectExecuteFlags_ = true;

private:
    static constexpr int NOTIFICATION_INTERVAL = 256;
};

} // namespace ghidra
