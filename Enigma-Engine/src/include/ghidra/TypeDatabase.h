#pragma once

#include <string>
#include <vector>
#include <memory>

namespace ghidra {

class TypeDatabase {
public:
    virtual ~TypeDatabase() = default;

    virtual bool getFunctionType(const std::string& funcName,
                                 std::string& returnType,
                                 std::vector<std::string>& paramTypes) const = 0;

    virtual bool isNoReturn(const std::string& funcName) const = 0;

    virtual std::string getPlatformName() const = 0;
};

enum class DetectedPlatform {
    Unknown,
    Windows,
    Linux,
    MacOS
};

DetectedPlatform detectPlatform(const std::string& binaryPath);
std::unique_ptr<TypeDatabase> createTypeDatabaseForPlatform(DetectedPlatform platform);
std::unique_ptr<TypeDatabase> createWindowsTypeDatabase();
std::unique_ptr<TypeDatabase> createLinuxTypeDatabase();
std::unique_ptr<TypeDatabase> createMacOSTypeDatabase();

} // namespace ghidra
