#pragma once

#include <string>
#include <map>
#include <vector>
#include <cstdint>

namespace ghidra {

typedef int32_t int4;
typedef int64_t int8;

class Options {
public:
    enum OptionType {
        TYPE_BOOL,
        TYPE_INT,
        TYPE_INT8,
        TYPE_STRING,
        TYPE_ENUM
    };

    struct Option {
        std::string name;
        OptionType type;
        std::string description;
        bool boolValue;
        int4 intValue;
        int8 int8Value;
        std::string stringValue;
        std::vector<std::string> enumValues;
        int4 enumIndex;
        bool isDefault;
    };

private:
    std::map<std::string, Option> options;
    std::string groupName;

public:
    Options(const std::string& group);
    ~Options() = default;

    void registerBool(const std::string& name, bool defaultValue, const std::string& desc);
    void registerInt(const std::string& name, int4 defaultValue, const std::string& desc);
    void registerInt8(const std::string& name, int8 defaultValue, const std::string& desc);
    void registerString(const std::string& name, const std::string& defaultValue, const std::string& desc);
    void registerEnum(const std::string& name, const std::vector<std::string>& values, int4 defaultIndex, const std::string& desc);

    bool getBool(const std::string& name) const;
    int4 getInt(const std::string& name) const;
    int8 getInt8(const std::string& name) const;
    std::string getString(const std::string& name) const;
    int4 getEnumIndex(const std::string& name) const;
    std::string getEnumValue(const std::string& name) const;

    void setBool(const std::string& name, bool value);
    void setInt(const std::string& name, int4 value);
    void setInt8(const std::string& name, int8 value);
    void setString(const std::string& name, const std::string& value);
    void setEnumIndex(const std::string& name, int4 index);
    void setEnumValue(const std::string& name, const std::string& value);

    bool hasOption(const std::string& name) const;
    OptionType getOptionType(const std::string& name) const;
    std::string getDescription(const std::string& name) const;
    std::vector<std::string> getEnumValues(const std::string& name) const;

    void resetToDefault(const std::string& name);
    void resetAllToDefaults();

    const std::string& getGroupName() const { return groupName; }
    int4 getNumOptions() const { return static_cast<int4>(options.size()); }
    const Option* getOption(const std::string& name) const;

    std::vector<std::string> getOptionNames() const;
};

class OptionsDatabase {
private:
    std::map<std::string, Options*> groups;

public:
    OptionsDatabase();
    ~OptionsDatabase();

    Options* getGroup(const std::string& name) const;
    Options* createGroup(const std::string& name);
    void removeGroup(const std::string& name);

    int4 getNumGroups() const { return static_cast<int4>(groups.size()); }
    std::vector<std::string> getGroupNames() const;

    void clear();
};

} // namespace ghidra
