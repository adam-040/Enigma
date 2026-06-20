#include <ghidra/TypeDatabase.h>
#include <string>
#include <memory>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

namespace ghidra {

static bool hasSuffix(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

DetectedPlatform detectPlatform(const std::string& binaryPath) {
    std::string lower = binaryPath;
    for (auto& c : lower) c = (char)std::tolower((unsigned char)c);

    if (hasSuffix(lower, ".exe") || hasSuffix(lower, ".dll") || hasSuffix(lower, ".sys") ||
        hasSuffix(lower, ".scr") || hasSuffix(lower, ".ocx") || hasSuffix(lower, ".cpl"))
        return DetectedPlatform::Windows;

    if (hasSuffix(lower, ".so") || hasSuffix(lower, ".elf") ||
        lower.find("lib") == 0 || binaryPath.find("/lib") != std::string::npos)
        return DetectedPlatform::Linux;

    if (hasSuffix(lower, ".dylib") || hasSuffix(lower, ".app") ||
        hasSuffix(lower, ".bundle") || hasSuffix(lower, ".macho"))
        return DetectedPlatform::MacOS;

    if (!std::filesystem::exists(binaryPath))
        return DetectedPlatform::Unknown;

    std::ifstream file(binaryPath, std::ios::binary);
    if (!file) return DetectedPlatform::Unknown;

    char magic[4]{};
    file.read(magic, 4);
    if (!file) return DetectedPlatform::Unknown;

    if (magic[0] == 'M' && magic[1] == 'Z')
        return DetectedPlatform::Windows;
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F')
        return DetectedPlatform::Linux;
    if ((static_cast<unsigned char>(magic[0]) == 0xFE &&
         static_cast<unsigned char>(magic[1]) == 0xED &&
         static_cast<unsigned char>(magic[2]) == 0xFA &&
         static_cast<unsigned char>(magic[3]) == 0xCE) ||
        (static_cast<unsigned char>(magic[0]) == 0xFE &&
         static_cast<unsigned char>(magic[1]) == 0xED &&
         static_cast<unsigned char>(magic[2]) == 0xFA &&
         static_cast<unsigned char>(magic[3]) == 0xCF) ||
        (static_cast<unsigned char>(magic[0]) == 0xCA &&
         static_cast<unsigned char>(magic[1]) == 0xFE &&
         static_cast<unsigned char>(magic[2]) == 0xBA &&
         static_cast<unsigned char>(magic[3]) == 0xBE) ||
        (static_cast<unsigned char>(magic[0]) == 0xCF &&
         static_cast<unsigned char>(magic[1]) == 0xFA &&
         static_cast<unsigned char>(magic[2]) == 0xED &&
         static_cast<unsigned char>(magic[3]) == 0xFE))
        return DetectedPlatform::MacOS;

    return DetectedPlatform::Unknown;
}

std::unique_ptr<TypeDatabase> createTypeDatabaseForPlatform(DetectedPlatform platform) {
    switch (platform) {
        case DetectedPlatform::Windows:
            return createWindowsTypeDatabase();
        case DetectedPlatform::Linux:
            return createLinuxTypeDatabase();
        case DetectedPlatform::MacOS:
            return createMacOSTypeDatabase();
        default:
            return nullptr;
    }
}

} // namespace ghidra
