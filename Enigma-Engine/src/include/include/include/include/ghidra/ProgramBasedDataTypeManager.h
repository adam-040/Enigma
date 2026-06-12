#pragma once

#include <ghidra/DomainFileBasedDataTypeManager.h>
#include <string>

namespace ghidra {

class Program;
class Data;
class SettingsDefinition;
class Address;
class TaskMonitor;

class ProgramBasedDataTypeManager : public virtual DomainFileBasedDataTypeManager {
public:
    virtual Program* getProgram() = 0;

    virtual bool isChangeAllowed(Data* data, SettingsDefinition* settingsDefinition) = 0;
    virtual bool setLongSettingsValue(Data* data, const std::string& name, long value) = 0;
    virtual bool setStringSettingsValue(Data* data, const std::string& name, const std::string& value) = 0;
    virtual bool setSettings(Data* data, const std::string& name, void* value) = 0;
    virtual long* getLongSettingsValue(Data* data, const std::string& name) = 0;
    virtual std::string* getStringSettingsValue(Data* data, const std::string& name) = 0;
    virtual void* getSettings(Data* data, const std::string& name) = 0;
    virtual bool clearSetting(Data* data, const std::string& name) = 0;
    virtual void clearAllSettings(Data* data) = 0;
    virtual std::vector<std::string> getInstanceSettingsNames(Data* data) = 0;
    virtual bool isEmptySetting(Data* data) = 0;

    virtual void moveAddressRange(Address* fromAddr, Address* toAddr, long length) = 0;
    virtual void deleteAddressRange(Address* startAddr, Address* endAddr) = 0;
};

} // namespace ghidra
