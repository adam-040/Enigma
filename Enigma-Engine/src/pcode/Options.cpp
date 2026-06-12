#include <ghidra/Options.h>
#include <stdexcept>
#include <algorithm>

namespace ghidra {

Options::Options(const std::string& group) : groupName(group) {
}

void Options::registerBool(const std::string& name, bool defaultValue, const std::string& desc) {
    Option opt;
    opt.name = name;
    opt.type = TYPE_BOOL;
    opt.description = desc;
    opt.boolValue = defaultValue;
    opt.isDefault = true;
    options[name] = opt;
}

void Options::registerInt(const std::string& name, int4 defaultValue, const std::string& desc) {
    Option opt;
    opt.name = name;
    opt.type = TYPE_INT;
    opt.description = desc;
    opt.intValue = defaultValue;
    opt.isDefault = true;
    options[name] = opt;
}

void Options::registerInt8(const std::string& name, int8 defaultValue, const std::string& desc) {
    Option opt;
    opt.name = name;
    opt.type = TYPE_INT8;
    opt.description = desc;
    opt.int8Value = defaultValue;
    opt.isDefault = true;
    options[name] = opt;
}

void Options::registerString(const std::string& name, const std::string& defaultValue, const std::string& desc) {
    Option opt;
    opt.name = name;
    opt.type = TYPE_STRING;
    opt.description = desc;
    opt.stringValue = defaultValue;
    opt.isDefault = true;
    options[name] = opt;
}

void Options::registerEnum(const std::string& name, const std::vector<std::string>& values, int4 defaultIndex, const std::string& desc) {
    Option opt;
    opt.name = name;
    opt.type = TYPE_ENUM;
    opt.description = desc;
    opt.enumValues = values;
    opt.enumIndex = defaultIndex;
    opt.isDefault = true;
    options[name] = opt;
}

bool Options::getBool(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_BOOL) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    return it->second.boolValue;
}

int4 Options::getInt(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_INT) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    return it->second.intValue;
}

int8 Options::getInt8(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_INT8) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    return it->second.int8Value;
}

std::string Options::getString(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_STRING) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    return it->second.stringValue;
}

int4 Options::getEnumIndex(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_ENUM) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    return it->second.enumIndex;
}

std::string Options::getEnumValue(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_ENUM) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    int4 idx = it->second.enumIndex;
    if (idx >= 0 && idx < static_cast<int4>(it->second.enumValues.size())) {
        return it->second.enumValues[idx];
    }
    return "";
}

void Options::setBool(const std::string& name, bool value) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_BOOL) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    it->second.boolValue = value;
    it->second.isDefault = false;
}

void Options::setInt(const std::string& name, int4 value) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_INT) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    it->second.intValue = value;
    it->second.isDefault = false;
}

void Options::setInt8(const std::string& name, int8 value) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_INT8) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    it->second.int8Value = value;
    it->second.isDefault = false;
}

void Options::setString(const std::string& name, const std::string& value) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_STRING) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    it->second.stringValue = value;
    it->second.isDefault = false;
}

void Options::setEnumIndex(const std::string& name, int4 index) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_ENUM) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    if (index >= 0 && index < static_cast<int4>(it->second.enumValues.size())) {
        it->second.enumIndex = index;
        it->second.isDefault = false;
    }
}

void Options::setEnumValue(const std::string& name, const std::string& value) {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_ENUM) {
        throw std::runtime_error("Option not found or wrong type: " + name);
    }
    for (int4 i = 0; i < static_cast<int4>(it->second.enumValues.size()); i++) {
        if (it->second.enumValues[i] == value) {
            it->second.enumIndex = i;
            it->second.isDefault = false;
            return;
        }
    }
}

bool Options::hasOption(const std::string& name) const {
    return options.find(name) != options.end();
}

Options::OptionType Options::getOptionType(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end()) return TYPE_BOOL;
    return it->second.type;
}

std::string Options::getDescription(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end()) return "";
    return it->second.description;
}

std::vector<std::string> Options::getEnumValues(const std::string& name) const {
    auto it = options.find(name);
    if (it == options.end() || it->second.type != TYPE_ENUM) return {};
    return it->second.enumValues;
}

void Options::resetToDefault(const std::string& name) {
    auto it = options.find(name);
    if (it == options.end()) return;

    it->second.isDefault = true;
    switch (it->second.type) {
        case TYPE_BOOL:
        case TYPE_INT:
        case TYPE_INT8:
        case TYPE_STRING:
            break;
        case TYPE_ENUM:
            it->second.enumIndex = 0;
            break;
    }
}

void Options::resetAllToDefaults() {
    for (auto& pair : options) {
        pair.second.isDefault = true;
    }
}

const Options::Option* Options::getOption(const std::string& name) const {
    auto it = options.find(name);
    return (it != options.end()) ? &it->second : nullptr;
}

std::vector<std::string> Options::getOptionNames() const {
    std::vector<std::string> names;
    for (const auto& pair : options) {
        names.push_back(pair.first);
    }
    return names;
}

OptionsDatabase::OptionsDatabase() {
}

OptionsDatabase::~OptionsDatabase() {
    clear();
}

Options* OptionsDatabase::getGroup(const std::string& name) const {
    auto it = groups.find(name);
    return (it != groups.end()) ? it->second : nullptr;
}

Options* OptionsDatabase::createGroup(const std::string& name) {
    auto it = groups.find(name);
    if (it != groups.end()) {
        return it->second;
    }
    auto* group = new Options(name);
    groups[name] = group;
    return group;
}

void OptionsDatabase::removeGroup(const std::string& name) {
    auto it = groups.find(name);
    if (it != groups.end()) {
        delete it->second;
        groups.erase(it);
    }
}

std::vector<std::string> OptionsDatabase::getGroupNames() const {
    std::vector<std::string> names;
    for (const auto& pair : groups) {
        names.push_back(pair.first);
    }
    return names;
}

void OptionsDatabase::clear() {
    for (auto& pair : groups) {
        delete pair.second;
    }
    groups.clear();
}

} // namespace ghidra
